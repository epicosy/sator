from abc import ABC, abstractmethod

from sator.core.models.product.references import ProductReferences


class ProductReferencesResolutionPort(ABC):

    @abstractmethod
    def search_product_references(self, vulnerability_id: str) -> ProductReferences | None:
        raise NotImplementedError
