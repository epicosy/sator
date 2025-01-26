from abc import ABC, abstractmethod
from typing import List

from sator.core.models.diff import Diff


class DiffRepositoryPort(ABC):
    @abstractmethod
    def get_diff(self, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_diffs(self) -> List[Diff]:
        raise NotImplementedError
