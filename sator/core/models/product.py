from dataclasses import dataclass
from sator.core.models.enums import ProductPart


@dataclass
class Product:
    name: str
    vendor: str
    part: ProductPart = None

    def __hash__(self):
        return hash((self.name, self.vendor))

    def __eq__(self, other):
        if not isinstance(other, Product):
            return False

        return self.name == other.name and self.vendor == other.vendor


@dataclass
class ProductOwnership:
    product: Product
    owner_id: int

    def __hash__(self):
        return hash((self.product, self.owner_id))

    def __eq__(self, other):
        if not isinstance(other, ProductOwnership):
            return False

        return self.product == other.product and self.owner_id == other.owner_id


@dataclass
class ProductLocator:
    product_ownership: ProductOwnership
    repository_id: int

    def __hash__(self):
        return hash((self.product_ownership, self.repository_id))

    def __eq__(self, other):
        if not isinstance(other, ProductLocator):
            return False

        return self.product_ownership == other.product_ownership and self.repository_id == other.repository_id
