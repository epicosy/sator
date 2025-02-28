from datetime import datetime
from typing import Tuple, List
from abc import ABC, abstractmethod

from sator.core.models.oss.diff import Diff


class OSSGatewayPort(ABC):
    @abstractmethod
    def get_diff(self, repo_id: int, commit_sha: str) -> Diff | None:
        raise NotImplementedError

    @abstractmethod
    def get_diff_info(self, repo_id: int, commit_sha: str) -> dict | None:
        raise NotImplementedError

    @abstractmethod
    def get_diff_url(self, repo_id: int, commit_sha: str) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def is_security_diff_message(self, message: str) -> bool | None:
        # TODO: temporary method to check if a commit message is related to a security fix
        #  should be moved to a more appropriate place

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

    def search_repo(self, owner_name: str, repository_name: str, n_org: int = 10, n_repos: int = 10) \
            -> Tuple[int | None, int | None]:
        """
            Search for a repository.

            :param owner_name: The owner name.
            :param repository_name: The repository name.
            :param n_org: The number of organizations to go through before giving up.
            :param n_repos: The number of repositories to go through before giving up.

            :return: A tuple containing the owner id and repository id.
        """
        raise NotImplementedError
