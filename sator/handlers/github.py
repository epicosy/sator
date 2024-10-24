import threading
import requests

from os import environ
from tqdm import tqdm
from pathlib import Path
from cement import Handler
from collections import deque
from typing import Union, List, Tuple

from github import Github
from github.Commit import Commit as GithubCommit
from github.Repository import Repository as GithubRepository
from github.GithubException import GithubException, RateLimitExceededException, UnknownObjectException

from sator.data.parsing import DiffBlock
from sator.core.exc import SatorGithubError
from sator.core.interfaces import HandlersInterface

from arepo.models.vcs.core.repository import RepositoryModel
from arepo.models.vcs.core.commit import CommitModel, CommitFileModel, CommitParentModel


class GithubHandler(HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._database_handler = None
        self._git_api: Github = None
        self._tokens: deque = None
        self.lock = threading.Lock()

    @property
    def database_handler(self):
        # TODO: this handler is repeated in all the handlers, should be moved to a base class
        if self._database_handler is None:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)

        return self._database_handler

    def _fetch_and_update_repo(self, repo_model: RepositoryModel):
        # TODO: this is the kind of info that can change over time, should be updated periodically
        git_repo = self.get_repo(repo_model.owner, project=repo_model.name)

        repo_model.available = bool(git_repo)
        repo_model.available = True
        repo_model.language = git_repo.language
        repo_model.description = git_repo.description
        repo_model.size = git_repo.size
        repo_model.stars = git_repo.stargazers_count
        repo_model.forks = git_repo.forks_count
        repo_model.watchers = git_repo.watchers_count
        repo_model.commits_count = git_repo.get_commits().totalCount

        # TODO: consider whether to add topics to the database
        # for topic in repo.topics:
        #    topic_digest = get_digest(topic)

        #    if not self.database_handler.has_id(topic_digest, TopicModel.__tablename__):
        #        self.database_handler.add_id(topic_digest, TopicModel.__tablename__)
        #         session.add(TopicModel(id=topic_digest, name=topic))
        #         session.commit()
        #
        #     session.add(RepositoryTopicModel(topic_id=topic_digest, repository_id=repo_model.id))

        return git_repo

    def _fetch_and_update_commit(self, commit_model: CommitModel, repo: GithubRepository):
        commit = None

        if repo:
            # TODO: check if it is a multiple parent commit
            commit = self.get_commit(repo, commit_sha=commit_model.sha)

            if commit:
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

        commit_model.available = bool(commit)

        return commit

    def fetch_git_data(self, language: str = None):
        # TODO: long method needs to be refactored
        session = self.app.db_con.get_session(scoped=True)

        if language:
            repo_query = session.query(RepositoryModel).filter(RepositoryModel.language == language)
        else:
            repo_query = session.query(RepositoryModel)

        self.app.log.info(f"Processing {repo_query.count()} repositories...")

        for repo_model in tqdm(repo_query.all()):
            # Skip repos that have been processed and are unavailable
            if repo_model.available is False:
                continue

            # If set and available, check if it has commits
            if repo_model.available and self.has_commits(repo_model.commits):
                self.app.log.info(f"Skipping {repo_model.owner}/{repo_model.name}...")
                continue

            # If not set, check if repo is available
            repo = self._fetch_and_update_repo(repo_model)

            for commit_model in tqdm(repo_model.commits, leave=False):
                if commit_model.available is False:
                    continue

                if (commit_model.available and commit_model.files_count is not None and
                        len(commit_model.files) == commit_model.files_count):
                    self.app.log.info(f"Skipping {commit_model.sha}...")
                    continue

                commit = self._fetch_and_update_commit(commit_model, repo)

                if commit:
                    # TODO: add self.database_handler.add_id(commit_model.id, CommitFileModel.__tablename__)

                    for f in commit.files:
                        patch = None

                        if f.patch:
                            patch = f.patch.strip()
                            # TODO: fix this hack
                            patch = patch.replace("\x00", "\uFFFD")

                        commit_file = CommitFileModel(commit_id=commit_model.id, filename=f.filename, raw_url=f.raw_url,
                                                      additions=f.additions, deletions=f.deletions, changes=f.changes,
                                                      status=f.status, extension=Path(f.filename).suffix, patch=patch)

                        session.add(commit_file)
                        # TODO: Add self.database_handler.add_id(commit_file.id, CommitFileModel.__tablename__)

                    commit_model.files_count = len(commit.files)

                    # TODO: to be included
                    # if commit_model.kind != 'parent':
                    #     self.update_parent_commits(session, repo, commit, commit_model)

                # Update every commit to make sure data persists when the process is interrupted
                session.commit()

    def run(self, **kwargs):
        self.fetch_git_data()

    def update_parent_commits(self, session, repo: GithubRepository, commit: GithubCommit,
                              commit_model: CommitModel) -> bool:
        # TODO: this needs to be refactored
        parent_commits_query = session.query(CommitParentModel).filter(CommitParentModel.commit_id == commit_model.id)
        parent_commits = [cp.parent_id for cp in parent_commits_query.all()]

        # if parent count not updated or some parents not stored
        if (commit_model.parents_count is None) or (len(parent_commits) != commit_model.parents_count):

            if commit is None:
                commit = self.get_commit(repo, commit_sha=commit_model.sha)

            for parent in commit.commit.parents:
                prent_commit_model = CommitModel(kind='parent', url=parent.url, sha=parent.sha,
                                                 repository_id=commit_model.repository_id,
                                                 vulnerability_id=commit_model.vulnerability_id)

                if not self.database_handler.has_id(prent_commit_model.id, CommitFileModel.__tablename__):
                    session.add(prent_commit_model)
                    session.commit()
                    self.database_handler.add_id(prent_commit_model.id, CommitFileModel.__tablename__)

                if prent_commit_model.id not in parent_commits:
                    session.add(CommitParentModel(commit_id=commit_model.id, parent_id=prent_commit_model.id))
                    session.commit()

            commit_model.parents_count = len(commit.commit.parents)
            session.commit()

            return True

        return False

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

    def has_rate_available(self):
        return self.git_api.get_rate_limit().core.remaining > 0

    @property
    def git_api(self):
        with self.lock:
            if not self._tokens:
                tokens = environ.get('GITHUB_TOKENS', None)

                if not tokens:
                    raise SatorGithubError("No GitHub tokens provided")

                split_tokens = tokens.split(',')
                self._tokens = deque(split_tokens, maxlen=len(split_tokens))

            if not self._git_api:
                self._git_api = Github(self._tokens[0])
                self._tokens.rotate(-1)

            count = 0
            while not self._git_api.get_rate_limit().core.remaining > 0:
                if count == len(self._tokens):
                    raise SatorGithubError(f"Tokens exhausted")
                self._git_api = Github(self._tokens[0])
                self._tokens.rotate(-1)
                count += 1

            return self._git_api

    @git_api.deleter
    def git_api(self):
        with self.lock:
            self._git_api = None

    def get_commit(self, repo: GithubRepository, commit_sha: str, raise_err: bool = False) -> Union[GithubCommit, None]:
        # Ignore unavailable commits
        try:
            # self.app.log.info(f"Getting commit {commit_sha}")
            return repo.get_commit(sha=commit_sha)
        except (ValueError, GithubException):
            err_msg = f"Commit {commit_sha} for repo {repo.name} unavailable: "
        except RateLimitExceededException as rle:
            err_msg = f"Rate limit exhausted: {rle}"

        if raise_err:
            raise SatorGithubError(err_msg)

        self.app.log.error(err_msg)

        return None

    def get_repo(self, owner: str, project: str, raise_err: bool = False) -> Union[GithubRepository, None]:
        repo_path = '{}/{}'.format(owner, project)

        try:
            self.app.log.info(f"Getting repo {repo_path}")
            return self.git_api.get_repo(repo_path)
        except RateLimitExceededException as rle:
            err_msg = f"Rate limit exhausted: {rle}"
        except UnknownObjectException:
            err_msg = f"Repo not found. Skipping {owner}/{project} ..."

        if raise_err:
            raise SatorGithubError(err_msg)

        self.app.log.error(err_msg)

        return None

    def get_diff(self, commit: GithubCommit) -> str:
        self.app.log.info(f"Requesting {commit.raw_data['html_url']}.diff")

        return requests.get(f"{commit.raw_data['html_url']}.diff").text

    def get_blocks_from_diff(self, diff_text: str, extensions: list = None) -> List[DiffBlock]:
        """
        Parses the input diff string and returns a list of result entries.

        :param diff_text: The input git diff string in unified diff format.
        :param extensions: file to include from the diff based on extensions.
        :return: A list of entries resulted from the input diff to be appended to the output csv file.
        """

        if not diff_text:
            return []

        # Look for a_path
        lines = diff_text.splitlines()
        diff_path_bound = [line_id for line_id in range(len(lines)) if lines[line_id].startswith("--- ")]
        num_paths = len(diff_path_bound)
        diff_path_bound.append(len(lines))
        blocks = []

        for path_id in range(num_paths):
            # Only look for a_paths with the interested file extensions
            if extensions and len(extensions) > 0:
                ext = Path(lines[diff_path_bound[path_id]]).suffix

                if ext not in extensions:
                    continue

            # Only consider file modification, ignore file additions for now
            block_start = diff_path_bound[path_id]
            if not lines[block_start + 1].startswith("+++ "):
                self.app.log.warning(f"Skipping block {block_start + 1} missing +++")
                continue

            # Ignore file deletions for now
            if not lines[block_start + 1].endswith(" /dev/null"):
                # Format of the "---" and "+++" lines:
                # --- a/<a_path>
                # +++ b/<b_path>
                diff_block = DiffBlock(start=block_start, a_path=lines[block_start][len("--- a/"):],
                                       b_path=lines[block_start + 1][len("+++ b/"):])

                # Do not include diff in the test files
                # TODO: should be provided as a parameter
                if "test" in diff_block.a_path or "test" in diff_block.b_path:
                    continue

                blocks.append(diff_block)

        return blocks

    def get_file_from_commit(self, repo_file_path: str, commit: GithubCommit, output_path: Path = None) \
            -> Tuple[str, Union[None, int]]:
        if output_path and output_path.exists() and output_path.stat().st_size != 0:
            self.app.log.info(f"{output_path} exists, reading...")

            with output_path.open(mode='r') as f:
                f_str = f.read()
        else:
            url = f"{commit.html_url}/{repo_file_path}".replace('commit', 'raw')
            self.app.log.info(f"Requesting {url}")
            f_str = requests.get(url).text

            if output_path:
                self.app.log.info(f"Writing {output_path}")
                output_path.parent.mkdir(exist_ok=True, parents=True)

                with output_path.open(mode="w") as f:
                    f.write(f_str)

        if output_path:
            return f_str, output_path.stat().st_size

        return f_str, None

    def get_repo_tags(self, owner: str, project: str, limit: int = None) -> List[str]:
        repo = self.get_repo(owner=owner, project=project)

        releases = repo.get_releases()

        if releases.totalCount > 0:
            if limit and releases.totalCount > limit:
                # Return the latest n releases
                return [release.tag_name for release in releases[:limit]]
            else:
                return [release.tag_name for release in releases]
        else:
            tags = repo.get_tags()
            if limit and tags.totalCount > limit:
                return [tag.name for tag in tags[:limit]]
            else:
                return [tag.name for tag in tags]
