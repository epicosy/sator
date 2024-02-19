import threading

from collections import deque
from typing import Union, List

from sator.core.exc import SatorGithubError
from sator.core.interfaces import HandlersInterface
from cement import Handler
from github import Github
from github.GithubException import GithubException, RateLimitExceededException, UnknownObjectException
from github.Repository import Repository
from github.Commit import Commit


class GithubHandler(HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._git_api: Github = None
        self._tokens: deque = None
        self.lock = threading.Lock()

    def has_rate_available(self):
        return self.git_api.get_rate_limit().core.remaining > 0

    @property
    def git_api(self):
        with self.lock:
            if not self._tokens:
                tokens = self.app.pargs.tokens.split(',')
                self._tokens = deque(tokens, maxlen=len(tokens))

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

    def get_commit(self, repo: Repository, commit_sha: str, raise_err: bool = False) -> Union[Commit, None]:
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

    def get_repo(self, owner: str, project: str, raise_err: bool = False) -> Union[Repository, None]:
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
