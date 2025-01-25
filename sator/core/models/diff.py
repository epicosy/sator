from typing import List, Iterator
from dataclasses import dataclass


@dataclass
class DiffLine:
    type: str
    lineno: int
    content: str

    def __str__(self):
        return self.content


@dataclass
class DiffHunk:
    old_start: int
    old_lines: List[DiffLine]
    new_start: int
    new_lines: List[DiffLine]

    def __iter__(self) -> Iterator[DiffLine]:
        return iter(self.old_lines + self.new_lines)

    def __str__(self):
        return "\n".join(str(line) for line in self)


@dataclass
class Patch:
    old_file: str
    new_file: str
    hunks: List[DiffHunk]

    def __iter__(self) -> Iterator[DiffHunk]:
        return iter(self.hunks)

    def __str__(self):
        return "\n".join(str(hunk) for hunk in self.hunks)


@dataclass
class Diff:
    commit_sha: str
    patches: List[Patch]

    def __iter__(self) -> Iterator[Patch]:
        return iter(self.patches)

    def __str__(self):
        return "\n".join(str(patch) for patch in self.patches)
