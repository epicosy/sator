from typing import List
from abc import ABC, abstractmethod

from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType


class ProductReferencePort(ABC):
    @abstractmethod
    def get_vendor_products(self, vendor_name: str) -> List[Product]:
        raise NotImplementedError

    @abstractmethod
    def get_product(self, vendor_name: str, product_name: str) -> Product | None:
        raise NotImplementedError

    @abstractmethod
    def get_product_references(self, vendor_name: str, product_name: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def get_product_part(self, product: Product) -> ProductPart:
        raise NotImplementedError

    @abstractmethod
    def get_product_type(self, product: Product) -> ProductType:
        raise NotImplementedError
