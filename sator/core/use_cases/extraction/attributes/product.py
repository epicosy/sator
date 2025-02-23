from typing import List

from sator.core.models.product.attributes import ProductAttributes
from sator.core.models.product.references import ProductReferences
from sator.core.models.vulnerability.locator import VulnerabilityLocator

from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driven.repositories.product import ProductRepositoryPort
from sator.core.ports.driving.extraction.attributes.product import ProductAttributesExtractionPort


class ProductAttributesExtraction(ProductAttributesExtractionPort):
    def __init__(self, storage_port: StoragePersistencePort, product_repositories: List[ProductRepositoryPort]):
        self.product_repositories = product_repositories
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

                versions = set()

                for product_repo in self.product_repositories:
                    versions.update(product_repo.get_versions(vulnerability_locator.product))

                # TODO: there should be a port for this, which performs the actual reference extraction
                product_attributes = ProductAttributes(
                    product=vulnerability_locator.product,
                    versions=list(versions),
                )

                self.storage_port.save(product_attributes, vulnerability_locator.product.id)
                return product_attributes

        return None
