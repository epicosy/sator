from abc import ABC, abstractmethod
from typing import List, Tuple

from sator.core.models.oss.diff import Diff


class OSSRepositoryPort(ABC):
    @abstractmethod
    def get_diff(self, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_diffs(self) -> List[Diff]:
        raise NotImplementedError

    @abstractmethod
    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None]:
        """
            Parse the URL and return the owner and repository ids.
        """
        raise NotImplementedError
