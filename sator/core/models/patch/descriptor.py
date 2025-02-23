from typing import Optional, List, Iterator
from pydantic import BaseModel, Field

from sator.core.models.enums import WeaknessType, PatchActionType, DiffChangeType, DiffContentType


class DiffHunkDescriptor(BaseModel):
    order: int
    change_type: DiffChangeType
    content_type: DiffContentType

    def __str__(self):
        return f"{self.order} - {self.change_type} - {self.content_type}"


class DiffPatchDescriptor(BaseModel):
    new_file: str
    hunks: List[DiffHunkDescriptor]

    def __iter__(self) -> Iterator[DiffHunkDescriptor]:
        return iter(self.hunks)

    def __str__(self):
        _str = f"{self.new_file}:"

        for hunk in self.hunks:
            _str += f"\n\t{hunk}"

        return _str


class DiffDescriptor(BaseModel):
    patches: List[DiffPatchDescriptor]

    def __iter__(self) -> Iterator[DiffPatchDescriptor]:
        return iter(self.patches)

    def __str__(self):
        return '\n'.join([str(patch) for patch in self.patches])


class PatchDescriptor(BaseModel):
    action_type: Optional[PatchActionType] = Field(default=None)
    weakness_type: Optional[WeaknessType] = Field(default=None)
    diff_descriptor: DiffDescriptor

    def __str__(self):
        return f"Action Type - {self.action_type} | Weakness Type - {self.weakness_type}\n{self.diff_descriptor}"
