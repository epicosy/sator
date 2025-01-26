from abc import ABC, abstractmethod

from sator.core.models.diff import Diff


class DiffGatewayPort(ABC):
    @abstractmethod
    def get_diff(self, repo_id: str, commit_sha: str) -> Diff | None:
        raise NotImplementedError
