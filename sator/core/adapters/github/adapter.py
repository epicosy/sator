from typing import Dict, List, Any, Union, Iterator

from sator.core.adapters.github.commit import CommitAdapter
from sator.core.adapters.github.repository import RepositoryAdapter


class GitToDBAdapter:
    # TODO: provide git object that encapsulates repo with all the respective commits, files, and diffs
    def __init__(self, git_repo, commits):
        self.repository_adapter = RepositoryAdapter(git_repo)
        # TODO: use official repository id when converting to model
        self.commit_adapter = CommitAdapter(git_repo.id, commits)

    def __call__(self) -> List[Union[Dict[str, Any], Iterator[Dict[str, Any]]]]:
        return [
            self.repository_adapter(),
            *self.commit_adapter()
        ]
