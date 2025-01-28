from abc import ABC, abstractmethod
from sator.core.models.product import Product
from sator.core.models.enums import ProductType


class ProductClassifierPort(ABC):
    @abstractmethod
    def classify_product_by_type(self, product: Product) -> ProductType:
        pass
