from abc import ABC, abstractmethod

from sator.core.models.product.attributes import ProductAttributes


class ProductAttributesExtractionPort(ABC):
    @abstractmethod
    def extract_product_attributes(self, product_id: str) -> ProductAttributes | None:
        raise NotImplementedError
