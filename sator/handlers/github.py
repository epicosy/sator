import threading
import requests

from pathlib import Path
from cement import Handler
from collections import deque
from typing import Union, List, Tuple

from github import Github
from github.Commit import Commit
from github.Repository import Repository
from github.GithubException import GithubException, RateLimitExceededException, UnknownObjectException

from sator.data.parsing import DiffBlock
from sator.core.exc import SatorGithubError
from sator.core.interfaces import HandlersInterface


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

    def get_diff(self, commit: Commit) -> str:
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

    def get_file_from_commit(self, repo_file_path: str, commit: Commit, output_path: Path = None) \
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
