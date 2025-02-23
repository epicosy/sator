from typing import Optional, List
from pydantic import BaseModel, Field


from sator.core.models.oss.diff import Diff


class PatchAttributes(BaseModel):
    action: Optional[str] = None
    flaw: Optional[str] = None
    version: Optional[str] = None
    sec_words: Optional[List[str]] = Field(default_factory=list)
    diff: Diff

    def __str__(self):
        return f"Action - {self.action} | Flaw - {self.flaw} | Security words - {self.sec_words}\n{self.diff}"
