from abc import ABC, abstractmethod

from sator.core.models.product.descriptor import ProductDescriptor


class ProductAnnotationPort(ABC):

    @abstractmethod
    def annotate_product(self, vendor_name: str, product_name: str) -> ProductDescriptor | None:
        """
            Annotate the given product with the product descriptor.

            Args:
                vendor_name: The name of the vendor.
                product_name: The name of the product.

            Returns:
                The product descriptor if the product exists, otherwise None.
        """
        raise NotImplementedError
