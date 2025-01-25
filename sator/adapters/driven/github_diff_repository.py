from typing import List

from gitlib.loader import DiffLoader

from sator.core.models.diff import Diff
from sator.adapters.driven.mappers.github_diff_mapper import GithubDiffMapper
from sator.core.ports.driven.diff_repository import DiffRepositoryPort


class GithubDiffRepository(DiffRepositoryPort):
    def __init__(self, path: str = '~/.gitlib'):
        self.loader = DiffLoader(path=path)
        self.diff_dict = self.loader.load()

    def get_diff(self, commit_sha: str) -> Diff | None:
        return self.diff_dict.entries.get(commit_sha, None)

    def get_diffs(self) -> List[Diff]:
        return [GithubDiffMapper.map_diff(sha, diff) for sha, diff in self.diff_dict.entries.items()]
