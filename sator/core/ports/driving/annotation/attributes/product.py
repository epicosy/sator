from abc import ABC, abstractmethod

from sator.core.models.product.descriptor import ProductDescriptor


class ProductAttributesAnnotationPort(ABC):

    @abstractmethod
    def annotate_product_attributes(self, product_id: str) -> ProductDescriptor | None:
        """
            Annotate the given product with the product descriptor.

            Args:
                product_id: The product identifier.

            Returns:
                The product descriptor if the product exists, otherwise None.
        """
        raise NotImplementedError
