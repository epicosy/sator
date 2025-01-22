from tqdm import tqdm
from typing import Dict, List, Iterator

from gitlib.github.commit import GitCommit
from arepo.models.vcs.core.commit import CommitModel

from sator.core.adapters.base import BaseAdapter
from sator.core.adapters.github.file import CommitFileAdapter


class CommitAdapter(BaseAdapter):
    def __init__(self, repo_id: str, commits: List[GitCommit]):
        super().__init__()
        self.repo_id = repo_id
        self.commits = commits

    def __call__(self) -> Iterator[Dict[str, CommitModel]]:
        for _commit in tqdm(self.commits, leave=False):
            commit_model = CommitModel(
                kind="Patch",  # TODO: provide kind type
                repository_id=self.repo_id,
                available=bool(_commit),  # TODO: unavailable commits should be stored in a different way
                sha=_commit.sha,
                date=_commit.date,
                state=_commit.state,
                url=_commit.html_url,
                author=_commit.commit.author.name.strip(),
                message=_commit.message.strip(),
                changes=_commit.stats.total,
                additions=_commit.stats.additions,
                deletions=_commit.stats.deletions,
                parents_count=len(_commit.parents)
            )

            yield from self.yield_if_new(commit_model, CommitModel.__tablename__)

            file_adapter = CommitFileAdapter(commit_model.id, _commit.files)

            yield from file_adapter()

            # TODO: understand if parent commits are still necessary and add them if that is the case

            # for parent in _commit.parents:
            #    parent_commit_model = CommitModel(kind='parent', url=parent.url, sha=parent.sha,
            #                                      repository_id=self.repo_id)

            #    yield from self.yield_if_new(parent_commit_model, CommitModel.__tablename__)

            #    commit_parent_model = CommitParentModel(commit_id=commit_model.id, parent_id=parent_commit_model.id)

            #    yield from self.yield_if_new(commit_parent_model, CommitParentModel.__tablename__)
