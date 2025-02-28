from sator.core.models.vulnerability.locator import VulnerabilityLocator
from sator.core.models.product import ProductAttributes, ProductReferences

from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.extraction.attributes.product import ProductAttributesExtractionPort


class ProductAttributesExtraction(ProductAttributesExtractionPort):
    def __init__(self, storage_port: StoragePersistencePort):
        self.storage_port = storage_port

    def extract_product_attributes(self, vulnerability_id: str) -> ProductAttributes | None:
        # TODO: vulnerability_id should be replaced with product_id in the method signature and skip vul locator
        vulnerability_locator = self.storage_port.load(VulnerabilityLocator, vulnerability_id)

        if vulnerability_locator:

            product_attributes = self.storage_port.load(ProductAttributes, vulnerability_locator.product.id)

            if product_attributes:
                return product_attributes

            product_references = self.storage_port.load(ProductReferences, vulnerability_locator.product.id)

            if product_references:
                # TODO: there should be a port for this, which performs the actual reference extraction
                product_attributes = ProductAttributes(
                    product=vulnerability_locator.product,
                )

                self.storage_port.save(product_attributes, vulnerability_locator.product.id)
                return product_attributes

        return None
