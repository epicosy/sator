from typing import Tuple

from gitlib.github.client import GitClient
from gitlib.github.repository import GitRepo
from gitlib.parsers.url.base import GithubUrlParser

from sator.core.models.oss.diff import Diff
from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.adapters.driven.repositories.oss.mappers import GithubDiffMapper


class GithubGateway(OSSGatewayPort):
    def __init__(self, login: str):
        self.github_client = GitClient(login)

    def get_diff(self, repo_id: str, commit_sha: str) -> Diff | None:
        # TODO: gitlib needs a method that fetches the repo by id or change the method signature to accept the repo path
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            diff = commit.get_diff()

            return GithubDiffMapper.map_diff(commit_sha, diff)

        return None

    def get_ids_from_url(self, url: str) -> Tuple[int | None, int | None]:
        github_url_parser = GithubUrlParser(url)
        github_object = github_url_parser()

        if github_object:
            git_repo = self.github_client.get_repo(github_object.owner, github_object.repo)

            if git_repo:
                return git_repo.owner.id, git_repo.id

        return None, None

