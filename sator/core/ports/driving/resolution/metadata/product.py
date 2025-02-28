from abc import ABC, abstractmethod

from sator.core.models.product.metadata import ProductMetadata


class ProductMetadataResolutionPort(ABC):
    @abstractmethod
    def resolve_metadata(self, product_id: str) -> ProductMetadata | None:
        """Method for getting a vulnerability by its ID."""
        raise NotImplementedError
