from typing import List

from sator.core.models.product import ProductMetadata, Product

from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driven.repositories.product import ProductRepositoryPort
from sator.core.ports.driving.resolution.metadata import ProductMetadataResolutionPort


class ProductMetadataResolution(ProductMetadataResolutionPort):
    def __init__(self, product_repositories: List[ProductRepositoryPort], storage_port: StoragePersistencePort):
        self.product_repositories = product_repositories
        self.storage_port = storage_port

    def resolve_metadata(self, name: str, vendor: str) -> ProductMetadata | None:
        product = Product(name=name, vendor=vendor)
        metadata = self.storage_port.load(ProductMetadata, product.id)

        if metadata:
            return metadata

        for product_repo in self.product_repositories:
            products = product_repo.search(vendor_name=vendor, product_name=name)

            if products:
                # TODO: Implement a port to select the most appropriate product
                product = products[0]
                versions = product_repo.get_versions(product)

                metadata = ProductMetadata(
                    name=product.name, vendor=product.vendor, versions=versions
                )

                self.storage_port.save(metadata, product.id)
                return metadata

        return None
