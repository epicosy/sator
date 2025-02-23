from abc import ABC, abstractmethod
from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType


class ProductClassifierPort(ABC):
    @abstractmethod
    def classify_product_by_part(self, product: Product) -> ProductPart:
        """
            Classify the given product by part.

            Args:
                product: The product to classify.

            Returns:
                The product part.
        """
        raise NotImplementedError

    @abstractmethod
    def classify_product_by_type(self, product_name: str, part: ProductPart) -> ProductType:
        """
            Classify the given product by type.

            Args:
                product_name: The product name.
                part: The product part.

            Returns:
                The product type.
        """
        raise NotImplementedError
