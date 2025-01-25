from typing import Union, Dict

from gitlib.github.repository import GitRepo
from sator.core.adapters.base import BaseAdapter
from arepo.models.vcs.core.repository import RepositoryModel


class RepositoryAdapter(BaseAdapter):
    def __init__(self, repo: GitRepo):
        super().__init__()
        self.repository = repo

    def __call__(self) -> Dict[str, Union[RepositoryModel | None]]:
        repo_model = RepositoryModel(
            id=self.repository.id,
            available=bool(self.repository),
            name=self.repository.name,
            owner=self.repository.owner.name,
            language=self.repository.language,
            description=self.repository.description,
            size=self.repository.size,
            stars=self.repository.stars,
            forks=self.repository.forks,
            watchers=self.repository.watchers,
            commits_count=self.repository.commits_count,
        )

        yield from self.yield_if_new(repo_model, RepositoryModel.__tablename__)
