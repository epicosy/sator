from abc import ABC
from typing import List

from sator.core.models.diff import Diff


class DiffRepositoryPort(ABC):
    def get_diff(self, commit_sha: str) -> Diff | None:
        pass

    def get_diffs(self) -> List[Diff]:
        pass
