from typing import Dict, List, Iterator

from gitlib.github.file import GitFile
from sator.core.adapters.base import BaseAdapter
from arepo.models.vcs.core.commit import CommitFileModel


class CommitFileAdapter(BaseAdapter):
    def __init__(self, commit_id: str, commit_files: List[GitFile]):
        super().__init__()
        self.commit_id = commit_id
        self.commit_files = commit_files

    def __call__(self) -> Iterator[Dict[str, CommitFileModel]]:
        for f in self.commit_files:
            # TODO: should call PatchAdapter to convert patch objects to models
            patch = None

            if f.patch:
                patch = f.patch.strip()
                # TODO: fix this hack
                patch = patch.replace("\x00", "\uFFFD")

            commit_file_model = CommitFileModel(commit_id=self.commit_id, filename=f.filename, raw_url=f.raw_url,
                                                additions=f.additions, deletions=f.deletions, changes=f.changes,
                                                status=f.status, extension=f.extension, patch=patch)

            yield from self.yield_if_new(commit_file_model, CommitFileModel.__tablename__)
