
from typing import List
from cpelib.types.definitions import CPEPart
from cpelib.core.loaders.json import JSONLoader

from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType
from sator.core.ports.driven.repositories.product import ProductReferencePort


CPE_PART_TO_PRODUCT_PART = {
    CPEPart.Application: ProductPart.APPLICATION,
    CPEPart.OS: ProductPart.OPERATING_SYSTEM,
    CPEPart.Hardware: ProductPart.HARDWARE,
}


class CPEDictionary(ProductReferencePort):
    def __init__(self, path: str):
        self.loader = JSONLoader(path)

    def get_vendor_products(self, vendor_name: str) -> List[Product]:
        # TODO: Implement this method
        return []

    def get_product(self, vendor_name: str, product_name: str) -> Product | None:
        cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)

        if len(cpe_dict) > 0:
            return Product(
                vendor=vendor_name,
                name=product_name,
            )

        return None

    def get_product_references(self, vendor_name: str, product_name: str) -> List[str]:
        cpe_dict = self.loader.load(vendor_name=vendor_name, product_name=product_name)

        return [ref.href for ref in cpe_dict.get_references()]

    def get_product_part(self, product: Product) -> ProductPart:
        cpe_dict = self.loader.load(vendor_name=product.vendor, product_name=product.name)

        if len(cpe_dict) > 0:
            first_item = list(cpe_dict.items.values())[0]
            return CPE_PART_TO_PRODUCT_PART[first_item.cpe.part]

        return ProductPart.UNDEFINED

    def get_product_type(self, product: Product) -> ProductType:
        return ProductType.UNDEFINED
