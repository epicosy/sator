from sator.core.models.product.attributes import ProductAttributes
from sator.core.models.product.references import ProductReferences

from sator.core.models.product import Product
from sator.core.models.product.locator import ProductOwnership, ProductLocator

from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.analysis.attributes.product import ProductAttributesAnalysisPort


class ProductAttributesAnalysis(ProductAttributesAnalysisPort):
    def __init__(self, oss_gateway: OSSGatewayPort, storage_port: StoragePersistencePort):
        self.oss_gateway = oss_gateway
        self.storage_port = storage_port

    def analyze_product_attributes(self, product_id: str) -> ProductLocator | None:
        product_locator = self.storage_port.load(ProductLocator, product_id)

        if product_locator:
            return product_locator

        product_attributes = self.storage_port.load(ProductAttributes, product_id)

        if product_attributes:
            locators = self._fetch_product_locators_from_references(product_attributes.product)

            if locators:
                # TODO: Implement a port to select the most appropriate locator
                product_locator = locators.pop()
                self.storage_port.save(product_locator, product_id)
                return product_locator
        else:
            # when there are no references, we should search for the product through the oss_gateway
            pass

        return None

    def _fetch_product_locators_from_references(self, product: Product) -> set[ProductLocator] | None:
        product_references = self.storage_port.load(ProductReferences, product.id)

        if product_references:
            locators = set()

            for reference in product_references.product + product_references.releases:
                owner_id, repo_id, diff_id = self.oss_gateway.get_ids_from_url(str(reference))

                # TODO: check if names are close enough to the product name

                if owner_id:
                    product_ownership = ProductOwnership(product=product, owner_id=owner_id)

                    if repo_id:
                        locator = ProductLocator(product_ownership=product_ownership, repository_id=repo_id)
                        locators.add(locator)

            return locators

        return None
