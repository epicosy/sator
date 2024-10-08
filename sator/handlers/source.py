import shutil
import requests
import functools

from tqdm import tqdm
from pathlib import Path
from cement import Handler
from requests import Response
from typing import Union, Tuple, List
from urllib.parse import urlparse

from sator.core.interfaces import HandlersInterface
from sator.handlers.github import GithubHandler
from sator.core.exc import SatorGithubError
from sator.utils.misc import get_digest

from github.Repository import Repository as GithubRepository
from github.Commit import Commit as GithubCommit
from github.File import File as GithubFile
from github.GitCommit import GitCommit

from arepo.models.vcs.core import RepositoryModel, CommitModel, CommitFileModel, CommitParentModel
from arepo.models.vcs.symbol import TopicModel, RepositoryTopicModel

from sqlalchemy.orm import Session


class SourceHandler(HandlersInterface, Handler):
    class Meta:
        label = 'source'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._github_handler: GithubHandler = None
        self._database_handler = None

    @property
    def database_handler(self):
        if not self._database_handler:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)
        return self._database_handler

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

        session.query(CommitModel).filter(CommitModel.repository_id == repo_model.id).update(
            {CommitModel.available: False})
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
            topic_digest = get_digest(topic)

            if not self.database_handler.has_id(topic_digest, TopicModel.__tablename__):
                self.database_handler.add_id(topic_digest, TopicModel.__tablename__)
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
        # todo check if it is a multiple parent commit
        # select most similar parent commit to be the commit
        # commit = most similar parent commit

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
        file_digest = get_digest(f"{commit_sha}/{file.filename}")
        patch = None
        session = self.app.db_con.get_session()

        if not self.database_handler.has_id(file_digest, CommitFileModel.__tablename__):
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
            self.database_handler.add_id(file_digest, CommitFileModel.__tablename__)

        return file_digest

    def update_commit_files(self, session: Session, repo: GithubRepository, commit_model: CommitModel,
                            commit: GithubCommit) -> bool:
        # TODO: probably need to pass session as argument to query the commit
        commit_files_query = session.query(CommitFileModel).filter(CommitFileModel.commit_id == commit_model.id)
        commit_files = [cf.id for cf in commit_files_query.all()]

        if (commit_model.files_count is None) or (len(commit_files) != commit_model.files_count):

            if commit is None:
                try:
                    commit = self.github_handler.get_commit(repo, commit_sha=commit_model.sha, raise_err=True)
                except SatorGithubError as sge:
                    self.app.log.error(f"Could not get commit {commit_model.sha}: {sge}")
                    return False

            for f in commit.files:
                self.update_commit_file(commit_model.id, commit_model.sha, f)

            commit_model.files_count = len(commit.files)
            session.commit()

            return True

        return False

    def update_parent_commit(self, commit_model: CommitModel, parent: GitCommit) -> str:
        session = self.app.db_con.get_session()
        parent_digest = get_digest(parent.url)

        if not self.database_handler.has_id(parent_digest, CommitFileModel.__tablename__):
            session.add(CommitModel(id=parent_digest, kind='parent', url=parent.url, sha=parent.sha,
                                    repository_id=commit_model.repository_id,
                                    vulnerability_id=commit_model.vulnerability_id))
            session.commit()
            self.database_handler.add_id(parent_digest, CommitFileModel.__tablename__)

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

    def update_commit(self, session: Session, repo: GithubRepository, commit_model: CommitModel):
        commit = None

        if commit_model.available is None:
            commit = self.update_awaiting_commit(session, repo, commit_model)

        if commit_model.available:
            self.update_commit_files(session, repo, commit_model, commit)

            if commit_model.kind != 'parent':
                self.update_parent_commits(session, repo, commit, commit_model)

    def add_metadata(self, language: str):
        self.database_handler.init_global_context()
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
