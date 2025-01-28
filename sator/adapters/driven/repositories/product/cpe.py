
from sator.core.ports.driven.repositories.product import ProductReferencePort


class CPEDictionary(ProductReferencePort):
    def get_vendor_products(self, vendor_name: str):
        pass

    def get_product_references(self, vendor_name: str, product_name: str):
        pass
