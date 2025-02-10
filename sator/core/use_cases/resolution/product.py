from typing import Dict, List

from sator.core.models.enums import ProductPart, ProductType
from sator.core.models.product import Product, AffectedProducts
from sator.core.models.product.descriptor import ProductDescriptor
from sator.core.models.product.locator import ProductOwnership, ProductLocator

from sator.core.ports.driven.gateways.oss import OSSGatewayPort
from sator.core.ports.driven.repositories.product import ProductReferencePort
from sator.core.ports.driven.persistence.storage import StoragePersistencePort
from sator.core.ports.driving.resolution.product import ProductResolutionPort


# Ranked by layer
PRODUCT_PART_SCORES = {
    ProductPart.HARDWARE: 1,
    ProductPart.OPERATING_SYSTEM: 2,
    ProductPart.APPLICATION: 3
}

# Ranked by granularity within the product part, i.e., each layer starts from 1, 0 goes to the undefined category
PRODUCT_TYPE_SCORES = {
    ProductType.UNDEFINED: 0,
    ProductType.EMBEDDED: 1,
    ProductType.FIRMWARE: 2,
    ProductType.DESKTOP: 3,
    ProductType.MOBILE: 4,
    ProductType.UTILITY: 5,
    ProductType.LIBRARY: 6,
    ProductType.FRAMEWORK: 7,
    ProductType.SERVER: 8,
    ProductType.DATABASE: 9,
    ProductType.WEB_APPLICATION: 10,
    ProductType.PLUGIN: 11
}


class ProductResolution(ProductResolutionPort):
    def __init__(self, product_reference_port: ProductReferencePort, oss_port: OSSGatewayPort,
                 storage_port: StoragePersistencePort):
        self.product_reference_port = product_reference_port
        self.oss_port = oss_port
        self.storage_port = storage_port

    def get_locators(self, vulnerability_id: str) -> Dict[str, ProductLocator]:
        """
            Get the product locators for the given product.

            Returns:
                A dictionary of product locators with the repository id as the key.
        """

        affected_products = self.storage_port.load(AffectedProducts, vulnerability_id)

        if not affected_products:
            return {}

        locators = {}

        for product in affected_products:
            product_key = f"{product.vendor} {product.name}"

            if product_key in locators:
                continue

            product_locator = self.storage_port.load(ProductLocator, product_key)

            if product_locator:
                locators[product_key] = product_locator
                continue

            references = self.product_reference_port.get_product_references(product)
            visited = set()

            for reference in references:
                if reference in visited:
                    continue

                visited.add(reference)
                owner_id, repo_id, _ = self.oss_port.get_ids_from_url(reference)

                if owner_id:
                    product_ownership = ProductOwnership(product=product, owner_id=owner_id)

                    if repo_id:
                        product_locator = ProductLocator(product_ownership=product_ownership, repository_id=repo_id)
                        locators[product_key] = product_locator

                        self.storage_port.save(product_locator, product_key)

        return locators

    def get_vulnerable_product(self, description: str, products_descriptors: List[ProductDescriptor]) -> Product | None:
        """
            Get the product that is most likely to be affected by the vulnerability.

            Args:
                description: The description of the vulnerability
                products_descriptors: The descriptors of the products that are affected by the vulnerability

            Returns:
                The product that is most likely to be affected by the vulnerability
        """
        # TODO: simplify method, there are two ways to get the product, either by the affected products or by the
        #  description, this one should be used when the affected products are available
        if len(products_descriptors) == 1:
            return products_descriptors[0].product

        # TODO: consider adding a port for extracting terms from the description into a structured format
        terms = description.lower().split()
        products_by_score = {}

        for product_descriptor in products_descriptors:
            if product_descriptor.product.name not in products_by_score:
                products_by_score[product_descriptor.product.name] = {
                    'score': PRODUCT_PART_SCORES[product_descriptor.part], 'product': product_descriptor.product
                }

            # TODO: consider also the weakness type in combination with the product type to determine the score
            products_by_score[product_descriptor.product.name]['score'] += PRODUCT_TYPE_SCORES[product_descriptor.type]

            # TODO: Implement other ways to match the product name with the vulnerability description.
            for term in terms:
                if term in product_descriptor.product.name.lower():
                    products_by_score[product_descriptor.product.name]['score'] += 1

        selection = max(products_by_score, key=lambda x: products_by_score[x]['score'])

        return products_by_score[selection]['product']
