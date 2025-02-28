from typing import List
from pydantic import BaseModel, Field

from sator.core.models.product import Product


class ProductAttributes(BaseModel):
    product: Product
    keywords: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)

    def __str__(self):
        return f"{self.product} with {len(self.keywords)} keywords and {len(self.platforms)} platforms"
