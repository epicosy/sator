from pydantic import BaseModel
from typing import List, Iterator


class DiffLine(BaseModel):
    type: str
    lineno: int
    content: str

    def __str__(self):
        return self.content


class DiffHunk(BaseModel):
    order: int
    old_start: int
    old_lines: List[DiffLine]
    new_start: int
    new_lines: List[DiffLine]

    @property
    def old_code(self):
        return "\n".join(str(line) for line in self.old_lines)

    @property
    def new_code(self):
        return "\n".join(str(line) for line in self.new_lines)

    def __iter__(self) -> Iterator[DiffLine]:
        return iter(self.old_lines + self.new_lines)

    def __str__(self):
        _str = f"Old Start: {self.old_start} | New Start: {self.new_start}"

        for line in self:
            _str += f"\n{line}"

        return _str


class Patch(BaseModel):
    old_file: str
    new_file: str
    hunks: List[DiffHunk]

    def __iter__(self) -> Iterator[DiffHunk]:
        return iter(self.hunks)

    def __str__(self):
        _str = f"Old File: {self.old_file} | New File: {self.new_file}"

        for hunk in self.hunks:
            _str += f"\n\t{hunk}"

        return _str


class Diff(BaseModel):
    repository_id: int
    commit_sha: str
    parent_commit_sha: str
    patches: List[Patch]

    def __iter__(self) -> Iterator[Patch]:
        return iter(self.patches)

    def __str__(self):
        _str = f"Commit: {self.commit_sha}"

        for patch in self.patches:
            _str += f"\n\t{patch}"

        return _str
