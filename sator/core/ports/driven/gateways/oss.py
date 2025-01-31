from typing import Tuple
from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff


class OSSGatewayPort(ABC):
    @abstractmethod
    def get_diff(self, repo_id: str, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None]:
        """
            Parse the URL and return the owner and repository ids.

            :param url: The URL to parse.

            :return: A tuple containing the owner and repository ids.
        """
        raise NotImplementedError
