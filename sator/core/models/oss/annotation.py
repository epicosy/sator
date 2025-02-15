from pydantic import BaseModel
from typing import List, Iterator


from sator.core.models.enums import DiffChangeType, DiffContentType


class DiffHunkAnnotation(BaseModel):
    order: int
    change_type: DiffChangeType
    content_type: DiffContentType

    def __str__(self):
        return f"{self.order} - {self.change_type} - {self.content_type}"


class PatchAnnotation(BaseModel):
    new_file: str
    hunks: List[DiffHunkAnnotation]

    def __iter__(self) -> Iterator[DiffHunkAnnotation]:
        return iter(self.hunks)

    def __str__(self):
        _str = f"{self.new_file}:"

        for hunk in self.hunks:
            _str += f"\n\t{hunk}"

        return _str


class DiffAnnotation(BaseModel):
    patches: List[PatchAnnotation]

    def __iter__(self) -> Iterator[PatchAnnotation]:
        return iter(self.patches)

    def __str__(self):
        _str = f""

        for patch in self.patches:
            _str += f"Patch: {patch}\n"

        return _str
