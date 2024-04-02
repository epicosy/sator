import hashlib
import re
import shutil
import requests
import functools
import threading
import dataclasses
import Levenshtein
from tqdm import tqdm
from pathlib import Path
from cement import Handler
from requests import Response
from typing import Union, Tuple, List
from urllib.parse import urlparse

from sator.core.exc import SatorError
from sator.core.interfaces import HandlersInterface
from sator.handlers.github import GithubHandler
from sator.handlers.multi_task import MultiTaskHandler

from github.Repository import Repository as GithubRepository
from github.Commit import Commit as GithubCommit
from github.File import File as GithubFile
from github.GitCommit import GitCommit
from github import BadCredentialsException
from arepo.models.common.scoring import CVSS2Model,  CVSS3Model
from arepo.models.common.vulnerability import VulnerabilityModel, TagModel, ReferenceModel
from arepo.models.common.weakness import CWEModel
from arepo.models.common.platform import ProductModel, VendorModel, ConfigurationModel, ConfigurationVulnerabilityModel

from arepo.models.vcs.core import RepositoryModel, CommitModel, CommitFileModel, CommitParentModel
from arepo.models.vcs.symbol import TopicModel, RepositoryTopicModel

from sqlalchemy.orm import Session


# captures pull requests and diffs
HOST_OWNER_REPO_REGEX = '(?P<host>(git@|https:\/\/)([\w\.@]+)(\/|:))(?P<owner>[\w,\-,\_]+)\/(?P<repo>[\w,\-,\_]+)(.git){0,1}((\/){0,1})'


@dataclasses.dataclass
class NormalizedCommit:
    owner: str
    repo: str
    sha: str
    url: str


class SourceHandler(HandlersInterface, Handler):
    class Meta:
        label = 'source'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._multi_task_handler: MultiTaskHandler = None
        self._github_handler: GithubHandler = None
        self.db_ids = {}
        self.tag_ids = {}
        self.cwe_ids = []
        self.lock = threading.Lock()

    def init_global_context(self):
        # TODO: too complex, simplify
        self.app.log.info("Initializing global context...")
        session = self.app.db_con.get_session()
        # Setup available tags and CWE-IDs

        for tag in session.query(TagModel).all():
            self.tag_ids[tag.name] = tag.id

        for cwe in session.query(CWEModel).all():
            self.cwe_ids.append(cwe.id)

        # Setup IDs in database
        self.app.log.info("Loading vuln IDs...")
        self.db_ids['vulns'] = set([cve.id for cve in session.query(VulnerabilityModel).all()])
        self.app.log.info("Loading ref IDs...")
        self.db_ids['refs'] = set([ref.id for ref in session.query(ReferenceModel).all()])
        self.app.log.info("Loading repo IDs...")
        self.db_ids['repos'] = set([repo.id for repo in session.query(RepositoryModel).all()])
        self.app.log.info("Loading commits IDs...")
        self.db_ids['commits'] = set([commit.id for commit in session.query(CommitModel).all()])
        self.app.log.info("Loading configs IDs...")
        self.db_ids['configs'] = set([config.id for config in session.query(ConfigurationModel).all()])
        self.app.log.info("Loading config_vuln IDs...")
        self.db_ids['config_vuln'] = set([f"{cv.configuration_id}_{cv.vulnerability_id}" for cv in session.query(ConfigurationVulnerabilityModel).all()])
        self.app.log.info("Loading products IDs...")
        self.db_ids['products'] = set([product.id for product in session.query(ProductModel).all()])
        self.app.log.info("Loading vendors IDs...")
        self.db_ids['vendors'] = set([vendor.id for vendor in session.query(VendorModel).all()])
        self.app.log.info("Loading commits files IDs...")
        self.db_ids['files'] = set([commit_file.id for commit_file in session.query(CommitFileModel).all()])
        self.app.log.info("Loading CVSS2 IDs...")
        self.db_ids['cvss2'] = set([cvss.id for cvss in session.query(CVSS2Model).all()])
        self.app.log.info("Loading CVSS3 IDs...")
        self.db_ids['cvss3'] = set([cvss.id for cvss in session.query(CVSS3Model).all()])
        self.app.log.info("Loading topics IDs...")
        self.db_ids['topics'] = set([topic.id for topic in session.query(TopicModel).all()])

    def has_id(self, _id: str, _type: str) -> bool:
        return _id in self.db_ids[_type]

    def add_id(self, _id: str, _type: str):
        with self.lock:
            self.db_ids[_type].add(_id)

    @staticmethod
    def get_digest(string: str):
        return hashlib.md5(string.encode('utf-8')).hexdigest()

    @property
    def multi_task_handler(self):
        if not self._multi_task_handler:
            self._multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)
        return self._multi_task_handler

    @multi_task_handler.deleter
    def multi_task_handler(self):
        self._multi_task_handler = None

    @property
    def github_handler(self):
        if not self._github_handler:
            self._github_handler = self.app.handler.get('handlers', 'github', setup=True)
        return self._github_handler

    @github_handler.deleter
    def github_handler(self):
        self._github_handler = None

    def download_file_from_url(self, url: str, extract: bool = False) -> Union[Tuple[Response, Path], None]:
        # TODO: checking by the name if the file exists is not reliable; we should also check the file size
        if 'http' not in url:
            self.app.lof.warning(f"URL {url} is not valid.")
            return None

        file_path = self.app.working_dir / Path(urlparse(url).path).name
        extract_file_path = self.app.working_dir / file_path.stem
        response = requests.get(url, stream=True, allow_redirects=True)

        if response.status_code != 200:
            self.app.log.error(f"Request to {url} returned status code {response.status_code}")
            return None

        total_size_in_bytes = int(response.headers.get('Content-Length', 0))

        if file_path.exists() and file_path.stat().st_size == total_size_in_bytes:
            self.app.log.warning(f"File {file_path} exists. Skipping download...")
        else:
            desc = "(Unknown total file size)" if total_size_in_bytes == 0 else ""
            response.raw.read = functools.partial(response.raw.read, decode_content=True)  # Decompress if needed

            with tqdm.wrapattr(response.raw, "read", total=total_size_in_bytes, desc=desc) as r_raw:
                with file_path.open("wb") as f:
                    shutil.copyfileobj(r_raw, f)

        if extract:
            if not extract_file_path.exists():
                self.app.log.info(f"Extracting file {extract_file_path}...")
                shutil.unpack_archive(file_path, self.app.working_dir)

            return response, extract_file_path

        return response, file_path

    @staticmethod
    def is_commit_reference(ref: str):
        match = re.search(r'(github|bitbucket|gitlab|git).*(/commit/|/commits/)', ref)

        if match:
            return match.group(1)

        return None

    def normalize_commit(self, ref: str) -> NormalizedCommit:
        """
            Normalizes commit reference
            returns tuple containing clean_commit, sha
        """

        if "CONFIRM:" in ref:
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}CONFIRM:
            ref = ref.replace("CONFIRM:", '')

        # FIXME: WTF? Find why...
        if "//commit" in ref:
            ref = ref.replace("//commit", "/commit")

        match_sha = re.search(r"\b[0-9a-f]{5,40}\b", ref)

        if not match_sha:
            # e.g., https://github.com/intelliants/subrion/commits/develop
            # e.g., https://gitlab.gnome.org/GNOME/gthumb/commits/master/extensions/cairo_io/cairo-image-surface-jpeg.c
            # e.g., https://github.com/{owner}/{repo}/commits/{branch}
            raise SatorError(f"Could not normalize commit")

        if 'git://' in ref and 'github.com' in ref:
            ref = ref.replace('git://', 'https://')

        if '/master?' in ref:
            # e.g., https://github.com/{owner}/{repo}/commits/master?after={sha}+{no_commits}
            raise SatorError(f"Could not normalize commit")

        if '#' in ref and ('#comments' in ref or '#commitcomment' in ref):
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}#commitcomment-{id}
            ref = ref.split('#')[0]

        if '.patch' in ref:
            # e.g., https://github.com/{owner}/{repo}/commit/{sha}.patch
            ref = ref.replace('.patch', '')
        if '%23' in ref:
            # e.g., https://github.com/absolunet/kafe/commit/c644c798bfcdc1b0bbb1f0ca59e2e2664ff3fdd0%23diff
            # -f0f4b5b19ad46588ae9d7dc1889f681252b0698a4ead3a77b7c7d127ee657857
            ref = ref.replace('%23', '#')

        # the #diff part in the url is used to specify the section of the page to display, for now is not relevant
        if "#diff" in ref:
            ref = ref.split("#")[0]
        if "?w=1" in ref:
            ref = ref.replace("?w=1", "")
        if "?branch=" in ref:
            ref = ref.split("?branch=")[0]
        if "?diff=split" in ref:
            ref = ref.replace("?diff=split", "")
        if re.match(r".*(,|/)$", ref):
            if "/" in ref:
                ref = ref[0:-1]
            else:
                ref = ref.replace(",", "")
        elif ")" in ref:
            ref = ref.replace(")", "")

        match = re.search(HOST_OWNER_REPO_REGEX, ref)

        if not match:
            raise SatorError(f"Could not extract owner/repo from commit url")

        return NormalizedCommit(owner=match['owner'], repo=match['repo'], sha=match_sha.group(0), url=ref)

    @staticmethod
    def has_commits(commits: List[CommitModel]):
        # check if repo has all commits available and has related files and parents
        for c in commits:
            # TODO: check for database for files and parents to avoid mismatches between count and actual entries
            if c.available is False:
                continue
            elif c.available is True:
                if c.kind != 'parent' and c.files_count and c.parents_count:
                    continue
                elif c.kind == 'parent' and c.files_count:
                    continue
                else:
                    return False
            else:
                return False

        return True

    def update_unavailable_repository(self, session: Session, repo_model: RepositoryModel):
        # TODO: probably need to pass session as argument to query the repository
        repo_model.available = False

        session.query(CommitModel).filter(CommitModel.repository_id == repo_model.id).update({CommitModel.available: False})
        session.commit()

    def update_awaiting_repository(self, session: Session, repo: GithubRepository, repo_model: RepositoryModel):
        # TODO: probably need to pass session as argument to query the repository

        repo_model.available = True
        repo_model.language = repo.language
        repo_model.description = repo.description
        repo_model.size = repo.size
        repo_model.stars = repo.stargazers_count
        repo_model.forks = repo.forks_count
        repo_model.watchers = repo.watchers_count
        repo_model.commits_count = repo.get_commits().totalCount

        for topic in repo.topics:
            topic_digest = self.get_digest(topic)

            if not self.has_id(topic_digest, 'topics'):
                self.add_id(topic_digest, 'topics')
                session.add(TopicModel(id=topic_digest, name=topic))
                session.commit()

            session.add(RepositoryTopicModel(topic_id=topic_digest, repository_id=repo_model.id))

        session.commit()

    def update_awaiting_commit(self, session: Session, repo: GithubRepository,
                               commit_model: CommitModel) -> Union[GithubCommit, None]:
        # TODO: probably need to pass session as argument to query the commit
        commit = self.github_handler.get_commit(repo, commit_sha=commit_model.sha)



        # add flag for available commits
        if not commit:
            session.query(CommitModel).filter(CommitModel.id == commit_model.id).update({CommitModel.available: False})
            session.commit()

            return None
        #todo check if it is a multiple parent commit
        #select most similar parent commit to be the commit
        #commit = most similar parent commit

        commit_model.author = commit.commit.author.name.strip()
        commit_model.message = commit.commit.message.strip()
        commit_model.changes = commit.stats.total
        commit_model.additions = commit.stats.additions
        commit_model.deletions = commit.stats.deletions
        commit_model.date = commit.commit.author.date
        commit_model.state = commit.get_combined_status().state

        if len(commit_model.sha) != 40 and commit_model.sha != commit.sha:
            commit_model.sha = commit.sha
            commit_model.url = commit.html_url

        commit_model.available = True
        session.commit()

        return commit

    def update_commit_file(self, commit_id: str, commit_sha: str, file: GithubFile) -> str:
        file_digest = self.get_digest(f"{commit_sha}/{file.filename}")
        patch = None
        session = self.app.db_con.get_session()

        if not self.has_id(file_digest, 'files'):
            if file.patch:
                patch = file.patch.strip()
                # TODO: fix this hack
                patch = patch.replace("\x00", "\uFFFD")
            # TODO: add programming language (Guesslang)

            commit_file = CommitFileModel(filename=file.filename, additions=file.additions, deletions=file.deletions,
                                          changes=file.changes, status=file.status, raw_url=file.raw_url, patch=patch,
                                          extension=Path(file.filename).suffix, commit_id=commit_id, id=file_digest)

            session.add(commit_file)
            session.commit()
            self.add_id(file_digest, 'files')

        return file_digest

    def update_commit_files(self, session: Session, repo: GithubRepository, commit_model: CommitModel,
                            commit: GithubCommit) -> bool:
        # TODO: probably need to pass session as argument to query the commit
        commit_files_query = session.query(CommitFileModel).filter(CommitFileModel.commit_id == commit_model.id)
        commit_files = [cf.id for cf in commit_files_query.all()]

        if (commit_model.files_count is None) or (len(commit_files) != commit_model.files_count):

            if commit is None:
                commit = self.github_handler.get_commit(repo, commit_sha=commit_model.sha, raise_err=True)

            for f in commit.files:
                self.update_commit_file(commit_model.id, commit_model.sha, f)

            commit_model.files_count = len(commit.files)
            session.commit()

            return True

        return False

    def update_parent_commit(self, commit_model: CommitModel, parent: GitCommit) -> str:
        session = self.app.db_con.get_session()
        parent_digest = self.get_digest(parent.url)

        if not self.has_id(parent_digest, 'commits'):
            session.add(CommitModel(id=parent_digest, kind='parent', url=parent.url, sha=parent.sha,
                                    repository_id=commit_model.repository_id,
                                    vulnerability_id=commit_model.vulnerability_id))
            session.commit()
            self.add_id(parent_digest, 'commits')

        return parent_digest
    

    def update_parent_commits(self, session: Session, repo: GithubRepository, commit: GithubCommit,
                              commit_model: CommitModel) -> bool:

        parent_commits_query = session.query(CommitParentModel).filter(CommitParentModel.commit_id == commit_model.id)
        parent_commits = [cp.parent_id for cp in parent_commits_query.all()]


        # if parent count not updated or some parents not stored 
        if (commit_model.parents_count is None) or (len(parent_commits) != commit_model.parents_count):

            if commit is None:
                commit = self.github_handler.get_commit(repo, commit_sha=commit_model.sha)

            for parent in commit.commit.parents:
                parent_digest = self.update_parent_commit(commit_model, parent)

                if parent_digest not in parent_commits:
                    session.add(CommitParentModel(commit_id=commit_model.id, parent_id=parent_digest))
                    session.commit()
          
            commit_model.parents_count = len(commit.commit.parents)
            session.commit()

            return True

        return False
    
        
    def update_parent_commits_test(self, session: Session, repo: GithubRepository, commit: GithubCommit,
                              commit_model: CommitModel) -> bool:

        parent_commits_query = session.query(CommitParentModel).filter(CommitParentModel.commit_id == commit_model.id)
        parent_commits = [cp.parent_id for cp in parent_commits_query.all()]
  
        # if parent count not updated or some parents not stored 
        if (commit_model.parents_count is None) or (len(parent_commits) != commit_model.parents_count):

            if commit is None:
                commit = self.github_handler.get_commit(repo, commit_sha=commit_model.sha)
            
            commit_text = None
            if commit:
                commit_text = self.github_handler.get_diff(commit)
                

            parent_len = commit.commit.parents
            
            most_similar_parent = commit.commit.parents[0]
            distance_to_commit = float('inf')
     
  
          
            for parent in commit.commit.parents:
                # only have one parent
                if(parent_len == 1):
                    most_similar_parent = parent
                    break 
                
                # have multiple parents
                parent_commit_text = None
                parent_commit = self.github_handler.get_commit(repo, commit_sha=parent.sha)
                if parent_commit:
                    parent_commit_text = self.github_handler.get_diff(parent_commit)
                #if all commit text available and they are the same
                if commit_text and parent_commit_text:
                    #if find a parent with identical diff content
                    if parent_commit_text == commit_text:
                        most_similar_parent = parent
                        break 
                    distance = Levenshtein.distance(commit_text, parent_commit_text)
                    if distance < distance_to_commit:
                        distance_to_commit = distance
                        most_similar_parent = parent

            #store the most similar parent in the database
            parent_digest = self.update_parent_commit(commit_model, most_similar_parent)

            if parent_digest not in parent_commits:
                    session.add(CommitParentModel(commit_id=commit_model.id, parent_id=parent_digest))
                    session.commit()
            
            #parent count become 1 instead of len(commit.commit.parents) because we only keep the most similar parent
            commit_model.parents_count = 1
            session.commit()
            return True 
         
        return False
    



    def update_commit(self, session: Session, repo: GithubRepository, commit_model: CommitModel):
        commit = None

        if commit_model.available is None:
            commit = self.update_awaiting_commit(session, repo, commit_model)

        if commit_model.available:
            self.update_commit_files(session, repo, commit_model, commit)

            if commit_model.kind != 'parent':
                self.update_parent_commits_test(session, repo, commit, commit_model)

    def add_metadata(self, language:str):
        self.init_global_context()
        session = self.app.db_con.get_session(scoped=True)
        if language:
            repo_query = session.query(RepositoryModel).filter(RepositoryModel.language == language)
        else:
            print("no lanaguge")
            repo_query = session.query(RepositoryModel)
      
        for repo_model in tqdm(repo_query.all()):


            if self.has_commits(repo_model.commits):
                self.app.log.info(f"Skipping {repo_model.owner}/{repo_model.name}...")
                continue

            self.app.log.info(f"Getting metadata for {repo_model.owner}/{repo_model.name}...")
            repo = self.github_handler.get_repo(repo_model.owner, project=repo_model.name)

            if not repo:
                self.update_unavailable_repository(session, repo_model)
                continue

            if repo_model.available is None:
             try:
                self.update_awaiting_repository(session, repo, repo_model)
             except Exception as exc:
                self.app.log.error(f"Repository {repo.name} is empty.")
            
                

            for commit_model in tqdm(repo_model.commits):
                self.update_commit(session, repo, commit_model)
