from rapidfuzz import fuzz
from datetime import datetime
from typing import Tuple, List

from secomlint.message import Message
from secomlint.section import Body, Header

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

    def is_security_diff_message(self, message: str) -> bool | None:
        commit_msg = [line.lower() for line in message.split('\n')]

        if not commit_msg:
            return None

        message_obj = Message(commit_msg)
        message_obj.get_sections()

        keyword_categories = {"SECWORD": [], "ACTION": [], "FLAW": []}

        for section in message_obj.sections:
            if isinstance(section, (Header, Body)):
                for entity in section.entities:
                    entity_text, entity_type = entity
                    if entity_type in keyword_categories:
                        keyword_categories[entity_type].append(entity_text)

        return all(keyword_categories[key] for key in keyword_categories)

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

    def search_repo(self, owner_name: str, repository_name: str, n_org: int = 10, n_repos: int = 10) \
            -> Tuple[int | None, int | None]:
        # TODO: elaborate the search to return the most relevant repository
        repo = self.github_client.get_repo(owner_name, repository_name)

        if repo:
            return repo.owner.id, repo.id

        orgs = self.github_client.git_api.search_users(owner_name)
        org_count = 0

        for org in orgs:
            if org_count >= n_org:
                print(f"Could not find {repository_name} in fetched organizations.")
                break

            if org.public_repos > 0:
                repo_count = 0
                print(f"Searching for {repository_name} in {org.login} organization.")
                repo = self.github_client.get_repo(org.login, repository_name)

                if repo:
                    return org.id, repo.id
                else:
                    for repo in org.get_repos():
                        if repo_count >= n_repos:
                            print(f"Could not find {repository_name} in fetched repositories.")
                            break

                        similarity = fuzz.ratio(repository_name, repo.name)
                        print(f"Comparing {repository_name} with {repo.name} - Similarity: {round(similarity, 3)}%")

                        if similarity > 85:
                            # This should be close enough
                            return org.id, repo.id

                        repo_count += 1

                org_count += 1

        return None, None

    def get_diff_info(self, repo_id: int, commit_sha: str) -> dict | None:
        repo = self.github_client.git_api.get_repo(repo_id)
        git_repo = GitRepo(repo)

        commit = git_repo.get_commit(commit_sha)

        if commit:
            return {
                'message': commit.message,
                'date': commit.date
            }

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
