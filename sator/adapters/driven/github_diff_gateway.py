from gitlib.github.client import GitClient
from gitlib.github.repository import GitRepo

from sator.core.models.diff import Diff
from sator.core.ports.driven.diff_gateway import DiffGatewayPort
from sator.adapters.driven.mappers.github_diff_mapper import GithubDiffMapper


class GithubDiffGateway(DiffGatewayPort):
    def __init__(self, token: str):
        self.github_client = GitClient(token)

    def get_diff(self, repo_id: str, commit_sha: str) -> Diff | None:
        # TODO: gitlib needs a method that fetches the repo by id or change the method signature to accept the repo path
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            diff = commit.get_diff()

            return GithubDiffMapper.map_diff(commit_sha, diff)

        return None
