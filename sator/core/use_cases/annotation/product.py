
from sator.core.models.product import Product
from sator.core.models.enums import ProductType
from sator.core.models.product.descriptor import ProductDescriptor
from sator.core.ports.driving.annotation.product import ProductAnnotationPort
from sator.core.ports.driven.classifiers.product import ProductClassifierPort
from sator.core.ports.driven.repositories.product import ProductReferencePort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort


class ProductAnnotation(ProductAnnotationPort):
    def __init__(self, product_reference_port: ProductReferencePort, product_classifier_port: ProductClassifierPort,
                 storage_port: StoragePersistencePort):
        self.product_reference_port = product_reference_port
        self.product_classifier_port = product_classifier_port
        self.storage_port = storage_port

    def annotate_product(self, vendor_name: str, product_name: str) -> ProductDescriptor | None:
        product = self.product_reference_port.get_product(vendor_name, product_name)

        if product:
            product_part = self.product_reference_port.get_product_part(product)
            product_type = self.product_reference_port.get_product_type(product)

            if product_type == ProductType.UNDEFINED:
                product_type = self.product_classifier_port.classify_product_by_type(product.name, product_part)

            product_descriptor = ProductDescriptor(
                product=product,
                type=product_type,
                part=product_part,
            )

            return product_descriptor

        return None
