from typing import List, Iterator, Union, Dict
from sator.core.adapters.base import BaseAdapter
from nvdutils.types.reference import CommitReference
from arepo.models.vcs.core.repository import RepositoryModel, RepositoryAssociationModel
from arepo.models.vcs.core.commit import CommitModel, CommitAssociationModel


class CommitAdapter(BaseAdapter):
    def __init__(self, cve_id: str, commits: List[CommitReference]):
        super().__init__()
        self.cve_id = cve_id
        self.commits = commits

    def __call__(self) -> Iterator[Dict[str, Union[RepositoryModel, RepositoryAssociationModel, CommitModel, CommitAssociationModel]]]:
        for commit in self.commits:
            if not (commit.tags and 'Patch' in commit.tags):
                # Skip commits that are not patches
                continue

            repo_model = RepositoryModel(name=commit.repo, owner=commit.owner)
            yield from self.yield_if_new(repo_model, RepositoryModel.__tablename__)

            # TODO: fix hardcoded source ids
            repo_assoc = RepositoryAssociationModel(
                repository_id=repo_model.id,
                vulnerability_id=self.cve_id,
                source_id='nvd_id'
            )

            yield from self.yield_if_new(repo_assoc, RepositoryAssociationModel.__tablename__)

            commit_model = CommitModel(sha=commit.sha, kind="Patch", repository_id=repo_model.id)

            yield from self.yield_if_new(commit_model, CommitModel.__tablename__)

            # TODO: fix hardcoded source ids
            commit_assoc = CommitAssociationModel(
                commit_id=commit_model.id,
                vulnerability_id=self.cve_id,
                source_id='nvd_id'
            )

            yield from self.yield_if_new(commit_assoc, CommitAssociationModel.__tablename__)
