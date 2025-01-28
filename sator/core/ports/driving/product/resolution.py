from typing import Dict
from abc import ABC, abstractmethod

from sator.core.models.product import Product, ProductLocator


class ProductResolutionPort(ABC):

    @abstractmethod
    def get_product_locators(self, product: Product) -> Dict[int, ProductLocator]:
        """Method for getting product locators."""
        raise NotImplementedError

    @abstractmethod
    def get_vulnerable_product(self, vulnerability_id: str) -> Product:
        """Method for getting the vulnerable product for a given vulnerability id."""
        raise NotImplementedError
