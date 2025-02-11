from typing import List
from pydantic import BaseModel


from sator.core.models.enums import DiffHunkType


class DiffHunkAnnotation(BaseModel):
    order: int
    type: DiffHunkType

    def __str__(self):
        return f"{self.order}: {self.type}"


class PatchAnnotation(BaseModel):
    old_file: str
    hunks: List[DiffHunkAnnotation]


class DiffAnnotation(BaseModel):
    commit_sha: str
    patches: List[PatchAnnotation]
