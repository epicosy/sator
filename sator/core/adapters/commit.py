from typing import List, Iterator, Union, Dict
from sator.utils.misc import get_digest
from sator.core.adapters.base import BaseAdapter
from nvdutils.types.reference import CommitReference
from arepo.models.vcs.core import RepositoryModel, CommitModel


class CommitAdapter(BaseAdapter):
    def __init__(self, cve_id: str, commits: List[CommitReference]):
        super().__init__()
        self.cve_id = cve_id
        self.commits = commits

    def __call__(self) -> Iterator[Dict[str, Union[RepositoryModel, CommitModel]]]:
        for commit in self.commits:
            repo_digest = get_digest(f"{commit.owner}/{commit.repo}")
            self._ids[RepositoryModel.__tablename__].add(repo_digest)
            yield {
                repo_digest: RepositoryModel(
                    id=repo_digest,
                    name=commit.repo,
                    owner=commit.owner
                )
            }

            commit_digest = get_digest(commit.processed_url)
            self._ids[CommitModel.__tablename__].add(commit_digest)
            # TODO: there should be a CommitVulnerability table, and the vulnerability_id should not be part of the
            #  CommitModel
            yield {
                commit_digest: CommitModel(
                    id=commit_digest,
                    url=commit.processed_url,
                    sha=commit.sha,
                    kind='|'.join(commit.tags),
                    vulnerability_id=self.cve_id,
                    repository_id=repo_digest
                )
            }
