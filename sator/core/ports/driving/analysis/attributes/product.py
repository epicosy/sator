from abc import ABC, abstractmethod

from sator.core.models.product.locator import ProductLocator


class ProductAttributesAnalysisPort(ABC):
    @abstractmethod
    def analyze_product_attributes(self, vulnerability_id: str) -> ProductLocator | None:
        raise NotImplementedError
