from typing import List, Optional, Iterator
from pydantic import BaseModel, Field, AnyUrl


class ProductReferences(BaseModel):
    website: Optional[List[AnyUrl]] = Field(default_factory=list)
    product: Optional[List[AnyUrl]] = Field(default_factory=list)
    releases: Optional[List[AnyUrl]] = Field(default_factory=list)
    advisories: Optional[List[AnyUrl]] = Field(default_factory=list)
    other: Optional[List[AnyUrl]] = Field(default_factory=list)

    def extend(self, references: "ProductReferences"):
        # TODO: check for duplicates
        self.website.extend(references.website)
        self.product.extend(references.product)
        self.releases.extend(references.releases)
        self.advisories.extend(references.advisories)
        self.other.extend(references.other)

    def to_list(self) -> List[AnyUrl]:
        return self.website + self.product + self.releases + self.advisories + self.other

    def __iter__(self) -> Iterator[AnyUrl]:
        return iter(self.to_list())

    def __len__(self):
        return len(self.to_list())

    def __str__(self):
        ref_categories = [
            ("website", self.website),
            ("product", self.product),
            ("releases", self.releases),
            ("advisories", self.advisories),
            ("other", self.other)
        ]

        ref_details = [f"{len(ref)} {name}" for name, ref in ref_categories if ref]
        ref_str = f"{len(self)} references" + (" (" + ", ".join(ref_details) + ")" if ref_details else "")

        return ref_str
