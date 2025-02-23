from pydantic import AnyUrl
from datetime import datetime
from typing import Tuple, List

from gitlib.github.client import GitClient
from gitlib.github.repository import GitRepo
from gitlib.models.url.commit import GithubCommitUrl
from gitlib.parsers.url.base import GithubUrlParser

from sator.core.models.oss.diff import Diff
from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.adapters.driven.repositories.oss.mappers import GithubDiffMapper


class GithubGateway(OSSGatewayPort):
    def __init__(self, login: str):
        self.github_client = GitClient(login)

    def search(self, repo_id: str, start_date: datetime, end_date: datetime, n: int) -> List[str]:
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        if git_repo:
            print(f"Searching for {n} commits in {git_repo.repo.full_name} repository "
                  f"between {start_date.date()} and {end_date.date()}.")
            commits = git_repo.repo.get_commits(since=start_date, until=end_date)

            if commits.totalCount > n:
                return [commit.sha for commit in commits[:n]]

            return [commit.sha for commit in commits]

        return []

    def get_diff_message(self, repo_id: int, commit_sha: str) -> str | None:
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            return commit.message

        return None

    def get_diff_url(self, repo_id: int, commit_sha: str) -> str | None:
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            return commit.html_url

        return None

    def get_diff(self, repo_id: int, commit_sha: str) -> Diff | None:
        # TODO: gitlib needs a method that fetches the repo by id or change the method signature to accept the repo path
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            diff = commit.get_diff()

            if commit.parents:
                return GithubDiffMapper.map_diff(repo_id, commit_sha, commit.parents[0].sha, diff)

        return None

    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None, str | None]:
        github_url_parser = GithubUrlParser(url)
        github_object = github_url_parser()

        if github_object:
            git_repo = self.github_client.get_repo(github_object.owner, github_object.repo)

            if git_repo:
                if isinstance(github_object, GithubCommitUrl):
                    # TODO: check also the commit for availability
                    return git_repo.owner.id, git_repo.id, github_object.sha

                return git_repo.owner.id, git_repo.id, None

        return None, None, None
