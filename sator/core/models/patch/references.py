from typing import List, Optional, Iterator
from pydantic import BaseModel, Field, AnyUrl


class PatchReferences(BaseModel):
    diffs: Optional[List[AnyUrl]] = Field(default_factory=list)
    messages: Optional[List[AnyUrl]] = Field(default_factory=list)
    other: Optional[List[AnyUrl]] = Field(default_factory=list)

    def extend(self, references: "PatchReferences"):
        self.diffs.extend(references.diffs)
        self.messages.extend(references.messages)
        self.other.extend(references.other)

    def to_list(self) -> List[AnyUrl]:
        return self.diffs + self.messages + self.other

    def __iter__(self) -> Iterator[AnyUrl]:
        return iter(self.to_list())

    def __len__(self):
        return len(self.to_list())

    def __str__(self):
        ref_categories = [
            ("diffs", self.diffs),
            ("messages", self.messages),
            ("other", self.other)
        ]

        ref_details = [f"{len(ref)} {name}" for name, ref in ref_categories if ref]
        ref_str = f"{len(self)} references" + (" (" + ", ".join(ref_details) + ")" if ref_details else "")

        return ref_str
