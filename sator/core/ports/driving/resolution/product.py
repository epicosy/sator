from typing import Dict, List
from abc import ABC, abstractmethod

from sator.core.models.product import Product
from sator.core.models.product.locator import ProductLocator


class ProductResolutionPort(ABC):

    @abstractmethod
    def get_product_locators(self, vendor_name: str, product_name: str) -> Dict[int, ProductLocator]:
        """Method for getting product locators."""
        raise NotImplementedError

    @abstractmethod
    def get_vulnerable_product(self, description: str, affected_products: List[Product]) -> Product:
        """Method for getting the vulnerable product from a list of affected products."""
        raise NotImplementedError
