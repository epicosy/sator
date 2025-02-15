from pydantic import BaseModel
from typing import List, Iterator


class Product(BaseModel):
    name: str
    vendor: str

    def __hash__(self):
        return hash((self.name, self.vendor))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.name == other.name and self.vendor == other.vendor


class AffectedProducts(BaseModel):
    vulnerability_id: str
    products: List[Product]

    def __iter__(self) -> Iterator[Product]:
        return iter(self.products)

    def __str__(self):
        _str = f"Vulnerability ID: {self.vulnerability_id}\n"

        for product in self.products:
            _str += f"\t{product}\n"

        return _str
