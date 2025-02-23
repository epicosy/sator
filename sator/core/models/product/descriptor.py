from pydantic import BaseModel
from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType, LicenseType


class ProductDescriptor(BaseModel):
    product: Product
    type: ProductType = ProductType.UNDEFINED
    part: ProductPart = ProductPart.UNDEFINED
    license_type: LicenseType = LicenseType.UNDEFINED

    def __hash__(self):
        return hash((self.product, self.type, self.part, self.license_type))

    def __eq__(self, other):
        if not isinstance(other, ProductDescriptor):
            return False

        return (self.product == other.product and self.type == other.type and self.part == other.part and
                self.license_type == other.license_type)
