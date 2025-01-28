from typing import List, Tuple

from gitlib.loader import DiffLoader

from sator.core.models.oss.diff import Diff
from sator.core.ports.driven.repositories.oss import OSSRepositoryPort
from sator.adapters.driven.repositories.oss.mappers import GithubDiffMapper

from gitlib.parsers.url.base import GithubUrlParser


class GithubRepository(OSSRepositoryPort):
    def __init__(self, path: str = '~/.gitlib'):
        self.loader = DiffLoader(path=path)
        self.diff_dict = self.loader.load()

    def get_diff(self, commit_sha: str) -> Diff | None:
        return self.diff_dict.entries.get(commit_sha, None)

    def get_diffs(self) -> List[Diff]:
        return [GithubDiffMapper.map_diff(sha, diff) for sha, diff in self.diff_dict.entries.items()]

    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None]:
        github_url_parser = GithubUrlParser(url)
        github_object = github_url_parser()

        if github_object:
            # TODO: needs to go through the store to get the owner and repo ids
            pass

        return None, None
