from abc import ABC, abstractmethod
from sator.core.models.product import Product
from sator.core.models.enums import ProductPart, ProductType, LicenseType


class ProductClassifierPort(ABC):
    @abstractmethod
    def classify_product_part(self, product: Product) -> ProductPart:
        """
            Classify the given product by part.

            Args:
                product: The product to classify.

            Returns:
                The product part.
        """
        raise NotImplementedError

    @abstractmethod
    def classify_product_type(self, product_name: str, part: ProductPart) -> ProductType:
        """
            Classify the given product by type.

            Args:
                product_name: The product name.
                part: The product part.

            Returns:
                The product type.
        """
        raise NotImplementedError

    @abstractmethod
    def classify_license_type(self, product: Product) -> LicenseType:
        """
            Classify the given product by license type.

            Args:
                product: The product to classify.

            Returns:
                The product license type.
        """
        raise NotImplementedError
