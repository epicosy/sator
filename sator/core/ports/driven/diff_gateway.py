from abc import ABC

from sator.core.models.diff import Diff


class DiffGatewayPort(ABC):
    def get_diff(self, repo_id: str, commit_sha: str) -> Diff | None:
        pass
