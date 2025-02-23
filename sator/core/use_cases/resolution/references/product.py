from typing import List

from sator.core.models.product import Product
from sator.core.models.product.references import ProductReferences
from sator.core.models.vulnerability.locator import VulnerabilityLocator
from sator.core.models.vulnerability.references import VulnerabilityReferences

from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driven.repositories.product import ProductRepositoryPort
from sator.core.ports.driving.resolution.references.product import ProductReferencesResolutionPort


class ProductReferencesResolution(ProductReferencesResolutionPort):
    def __init__(self, product_repositories: List[ProductRepositoryPort], storage_port: StoragePersistencePort):
        self.product_repositories = product_repositories
        self.storage_port = storage_port

    def search_product_references(self, vulnerability_id: str) -> ProductReferences | None:
        # TODO: make this methods more maintainable
        locator = self.storage_port.load(VulnerabilityLocator, vulnerability_id)

        if locator:
            product_references = self.storage_port.load(ProductReferences, locator.product.id)

            if not product_references:
                product_references = self._get_product_references(locator.product)

            if product_references:
                vulnerability_references = self.storage_port.load(VulnerabilityReferences, vulnerability_id)

                if vulnerability_references:
                    # check if there are vuln refs that are not in product refs
                    new_refs = set(vulnerability_references.product) - set(product_references.product)

                    if new_refs:
                        product_references.product.extend(new_refs)

                self.storage_port.save(product_references, locator.product.id)

            return product_references

        return None

    def _get_product_references(self, product: Product) -> ProductReferences | None:
        product_references = None

        # TODO: find a better way to do this
        for port in self.product_repositories:
            references = port.get_product_references(product)

            if not product_references:
                product_references = references
            else:
                product_references.extend(references)

        return product_references
