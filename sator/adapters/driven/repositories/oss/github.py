from typing import List

from gitlib.loader import DiffLoader

from sator.core.models.oss.diff import Diff
from sator.core.ports.driven.repositories.oss import OSSRepositoryPort
from sator.adapters.driven.repositories.oss.mappers import GithubDiffMapper


class GithubRepository(OSSRepositoryPort):
    def __init__(self, path: str):
        self.loader = DiffLoader(path=path)
        self.diff_dict = self.loader.load()

    def get_diff(self, commit_sha: str) -> Diff | None:
        return self.diff_dict.entries.get(commit_sha, None)

    def get_diffs(self) -> List[Diff]:
        return [GithubDiffMapper.map_diff(sha, diff) for sha, diff in self.diff_dict.entries.items()]

