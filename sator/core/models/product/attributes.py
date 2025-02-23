from typing import List
from pydantic import BaseModel

from sator.core.models.product import Product


class ProductAttributes(BaseModel):
    product: Product
    versions: List[str]

    def __str__(self):
        return f"{self.product} | {len(self.versions)} versions"
