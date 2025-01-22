from tqdm import tqdm
from os import environ
from cement import Handler
from typing import List, Dict


from arepo.base import Base
from arepo.models.vcs.core.repository import RepositoryModel
from arepo.models.vcs.core.commit import CommitParentModel

from gitlib.models.diff import Diff
from gitlib.loader import DiffLoader
from gitlib.github.client import GitClient

from sator.handlers.database import DatabaseHandler
from sator.core.interfaces import HandlersInterface
from sator.core.adapters.github.diff import DiffAdapter


class GithubHandler(HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._git_client = None
        self._database_handler: DatabaseHandler = None

    @property
    def database_handler(self):
        if self._database_handler is None:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)

        return self._database_handler

    @property
    def git_client(self):
        if self._git_client is None:
            token = environ.get('GITHUB_TOKEN', None)

            if token is None:
                raise ValueError("GITHUB_TOKEN variable not set")

            self._git_client = GitClient(token)

        return self._git_client

    def run(self, **kwargs):
        loader = DiffLoader(path='~/.gitlib')

        diff_dict = loader.load()
        entities = self.process(diff_dict.entries)

        print(entities)

        # self.database_handler.bulk_insert_in_order(processed_batches)

    def process(self, diffs_dict: Dict[str, Diff]) -> List[Dict[str, Base]]:
        # TODO: implement this method to

        res = []

        for sha, diff in diffs_dict.items():
            # TODO: provided id is a temporary solution
            git_adapter = DiffAdapter("1", diff)
            res.extend(git_adapter())

        return res

    # TODO: this belongs to an adapter that converts database models to objects
    def fetch_git_data(self, language: str = None, available: bool = False):
        session = self.app.db_con.get_session(scoped=True)

        if language:
            repo_query = session.query(RepositoryModel).filter(RepositoryModel.language == language)
        else:
            repo_query = session.query(RepositoryModel)

        self.app.log.info(f"Processing {repo_query.count()} repositories...")

        for repo_model in tqdm(repo_query.all()):
            # Skip repos that have been processed and are unavailable
            if available and repo_model.available is False:
                continue

            # If set and available, check if it has commits
            if repo_model.available and repo_model.has_commits(available=True, has_files=True, has_parents=True):
                self.app.log.info(f"Skipping {repo_model.owner}/{repo_model.name}...")
                continue

            # convert repo to an object

            for commit_model in tqdm(repo_model.commits, leave=False):
                if commit_model.available is False:
                    continue

                if (commit_model.available and commit_model.files_count is not None and
                        len(commit_model.files) == commit_model.files_count):
                    self.app.log.info(f"Skipping {commit_model.sha}...")
                    continue

                # convert commit to an object

                # TODO: this needs to be refactored
                parent_commits_query = session.query(CommitParentModel).filter(
                    CommitParentModel.commit_id == commit_model.id)
                parent_commits = [cp.parent_id for cp in parent_commits_query.all()]

                # convert parent commits to an object
