from typing import List, Iterator, Union, Dict
from sator.utils.misc import get_digest
from sator.core.adapters.base import BaseAdapter
from arepo.models.vcs.core.repository import RepositoryModel, RepositoryAssociationModel
from arepo.models.vcs.core.commit import CommitModel, CommitAssociationModel
from osvutils.types.range import GitRange


class CommitAdapter(BaseAdapter):
    def __init__(self, cve_id: str, ranges: List[GitRange]):
        super().__init__()
        self.cve_id = cve_id
        self.ranges = ranges

    def __call__(self) -> Iterator[Dict[str, Union[RepositoryModel, CommitModel]]]:
        for git_range in self.ranges:
            repo_model = RepositoryModel(
                name=git_range.repo.name,
                owner=git_range.repo.owner
            )

            yield from self.yield_if_new(repo_model, RepositoryModel.__tablename__)

            # TODO: fix hardcoded source ids
            repo_assoc = RepositoryAssociationModel(
                repository_id=repo_model.id,
                vulnerability_id=self.cve_id,
                source_id='osv_id'
            )

            yield from self.yield_if_new(repo_assoc, RepositoryAssociationModel.__tablename__)

            # TODO: should also consider commits that introduce the vulnerability
            for fix_event in git_range.get_fixed_events():
                commit_model = CommitModel(
                    sha=fix_event.version,
                    kind="Patch",
                    repository_id=repo_model.id
                )

                yield from self.yield_if_new(commit_model, CommitModel.__tablename__)

                # TODO: fix hardcoded source ids
                commit_assoc = CommitAssociationModel(
                    commit_id=commit_model.id,
                    vulnerability_id=self.cve_id,
                    source_id='osv_id'
                )

                yield from self.yield_if_new(commit_assoc, CommitAssociationModel.__tablename__)
