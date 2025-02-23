from sator.core.models.enums import ProductType
from sator.core.models.product.attributes import ProductAttributes
from sator.core.models.product.descriptor import ProductDescriptor

from sator.core.ports.driven.classifiers.product import ProductClassifierPort
from sator.core.ports.driven.repositories.product import ProductRepositoryPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.annotation.attributes.product import ProductAttributesAnnotationPort


class ProductAttributesAnnotation(ProductAttributesAnnotationPort):
    def __init__(self, product_reference_port: ProductRepositoryPort, product_classifier_port: ProductClassifierPort,
                 storage_port: StoragePersistencePort):
        self.product_reference_port = product_reference_port
        self.product_classifier_port = product_classifier_port
        self.storage_port = storage_port

    def annotate_product_attributes(self, product_id: str) -> ProductDescriptor | None:
        product_descriptor = self.storage_port.load(ProductDescriptor, product_id)

        if product_descriptor:
            return product_descriptor

        product_attributes = self.storage_port.load(ProductAttributes, product_id)

        if product_attributes:
            product_part = self.product_reference_port.get_product_part(product_attributes.product)
            product_type = self.product_reference_port.get_product_type(product_attributes.product)

            if product_type == ProductType.UNDEFINED:
                product_type = self.product_classifier_port.classify_product_by_type(
                    product_attributes.product.name, product_part
                )

            # TODO: provide the license type, for now it is set to UNDEFINED
            product_descriptor = ProductDescriptor(
                product=product_attributes.product,
                type=product_type,
                part=product_part,
            )

            self.storage_port.save(product_descriptor, product_id)
            return product_descriptor

        return None
