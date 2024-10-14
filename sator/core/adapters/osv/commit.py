from typing import List, Iterator, Union, Dict
from sator.utils.misc import get_digest
from sator.core.adapters.base import BaseAdapter
from arepo.models.vcs.core import RepositoryModel, CommitModel
from osvutils.types.range import GitRange


class CommitAdapter(BaseAdapter):
    def __init__(self, cve_id: str, ranges: List[GitRange]):
        super().__init__()
        self.cve_id = cve_id
        self.ranges = ranges

    def __call__(self) -> Iterator[Dict[str, Union[RepositoryModel, CommitModel]]]:
        for git_range in self.ranges:
            repo_digest = get_digest(str(git_range.repo))

            self._ids[RepositoryModel.__tablename__].add(repo_digest)
            yield {
                repo_digest: RepositoryModel(
                    id=repo_digest,
                    name=git_range.repo.name,
                    owner=git_range.repo.owner
                )
            }

            # TODO: there should be a RepositoryVulnerability table to keep track of the vulns in a repo

            # TODO: should also consider commits that introduce the vulnerability
            for fix_event in git_range.get_fixed_events():
                # TODO: should use sha as the id
                commit_digest = get_digest(f"{str(git_range.repo)}_{fix_event.version}")
                self._ids[CommitModel.__tablename__].add(commit_digest)
                # TODO: there should be a CommitVulnerability table, and the vulnerability_id should not be part of the
                #  CommitModel
                yield {
                    commit_digest: CommitModel(
                        id=commit_digest,
                        url="",  # TODO: should be removed from the model
                        sha=fix_event.version,
                        kind="Patch",
                        vulnerability_id=self.cve_id,
                        repository_id=repo_digest  # TODO: probably there should be a RepositoryCommit table instead
                    )
                }
