from typing import List
from abc import ABC, abstractmethod

from sator.core.models.product import Product


class ProductReferencePort(ABC):
    @abstractmethod
    def get_vendor_products(self, vendor_name: str) -> List[Product]:
        raise NotImplementedError

    @abstractmethod
    def get_product_references(self, vendor_name: str, product_name: str) -> List[str]:
        raise NotImplementedError
