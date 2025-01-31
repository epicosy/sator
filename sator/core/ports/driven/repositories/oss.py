from typing import List
from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff


class OSSRepositoryPort(ABC):
    @abstractmethod
    def get_diff(self, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_diffs(self) -> List[Diff]:
        raise NotImplementedError
