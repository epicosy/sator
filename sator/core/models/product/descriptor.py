from dataclasses import dataclass

from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType


@dataclass
class ProductDescriptor:
    product: Product
    type: ProductType = ProductType.UNDEFINED
    part: ProductPart = ProductPart.UNDEFINED

    def __hash__(self):
        return hash((self.product, self.type, self.part))

    def __eq__(self, other):
        if not isinstance(other, ProductDescriptor):
            return False

        return self.product == other.product and self.type == other.type and self.part == other.part
