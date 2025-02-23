from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff


class DiffResolutionPort(ABC):
    @abstractmethod
    def get_diff(self, vulnerability_id: str) -> Diff | None:
        """Method for getting a diff by its ID."""
        raise NotImplementedError
