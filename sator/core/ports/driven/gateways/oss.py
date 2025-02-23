from datetime import datetime
from typing import Tuple, List
from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff


class OSSGatewayPort(ABC):
    @abstractmethod
    def get_diff(self, repo_id: int, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_diff_message(self, repo_id: int, commit_sha: str) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def get_diff_url(self, repo_id: int, commit_sha: str) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None, str | None]:
        """
            Parse the URL and return the owner and repository ids.

            :param url: The URL to parse.

            :return: A tuple containing the owner id, repository id, and the hash of the commit.
        """
        raise NotImplementedError

    @abstractmethod
    def search(self, repo_id: int, start_date: datetime, end_date: datetime, n: int) -> List[str]:
        """
            Search for a commit in a repository.

            :param repo_id: The repository id.
            :param start_date: The start date to search for.
            :param end_date: The end date to search for.
            :param n: The number of commits to return.

            :return: A list of commit hashes.
        """
        raise NotImplementedError
