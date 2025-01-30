from typing import Dict

from sator.core.models.enums import ProductPart, ProductType
from sator.core.models.product import Product, ProductOwnership, ProductLocator

from sator.core.ports.driven.repositories.vulnerability import VulnerabilityRepositoryPort
from sator.core.ports.driven.classifiers.product import ProductClassifierPort
from sator.core.ports.driving.product.resolution import ProductResolutionPort
from sator.core.ports.driven.repositories.oss import OSSRepositoryPort
from sator.core.ports.driven.repositories.product import ProductReferencePort


# Ranked by layer
PRODUCT_PART_SCORES = {
    ProductPart.HARDWARE: 1,
    ProductPart.OPERATING_SYSTEM: 2,
    ProductPart.APPLICATION: 3
}

# Ranked by granularity within the product part, i.e., each layer starts from 1, 0 goes to the undefined category
PRODUCT_TYPE_SCORES = {
    ProductType.UNDEFINED: 0,
    ProductType.FIRMWARE: 1,
    ProductType.UTILITY: 1,
    ProductType.LIBRARY: 2,
    ProductType.FRAMEWORK: 3,
    ProductType.SERVER: 4,
    ProductType.DATABASE: 5,
    ProductType.WEB_APPLICATION: 6,
    ProductType.PLUGIN: 7
}


class ProductResolution(ProductResolutionPort):
    def __init__(self, vulnerability_port: VulnerabilityRepositoryPort, product_classifier_port: ProductClassifierPort,
                 product_reference_port: ProductReferencePort, oss_port: OSSRepositoryPort):
        self.vulnerability_port = vulnerability_port
        self.product_classifier_port = product_classifier_port
        self.product_reference_port = product_reference_port
        self.oss_port = oss_port

    def get_product_locators(self, product: Product) -> Dict[int, ProductLocator]:
        """
            Get the product locators for the given product.

            Args:
                product: The product to get the locators for.

            Returns:
                A dictionary of product locators with the repository id as the key.
        """

        locators = {}

        references = self.product_reference_port.get_product_references(product.vendor, product.name)
        visited = set()

        for reference in references:
            if reference in visited:
                continue

            visited.add(reference)
            owner_id, repo_id = self.oss_port.get_ids_from_url(reference)

            if owner_id:
                product_ownership = ProductOwnership(product, owner_id)

                if repo_id:
                    product_locator = ProductLocator(product_ownership, repo_id)

                    if repo_id not in locators:
                        locators[repo_id] = product_locator

        return locators

    def get_vulnerable_product(self, vulnerability_id: str) -> Product | None:
        """
            Get the product that is vulnerable to the given vulnerability.

            Args:
                vulnerability_id: The id of the vulnerability to get the product for.

            Returns:
                The product that is vulnerable to the given vulnerability.
        """
        vulnerability = self.vulnerability_port.get_vulnerability(vulnerability_id)

        if not vulnerability:
            return {"error": f"Failed to get vulnerability data for {vulnerability_id}"}

        if not vulnerability.description:
            return {"error": f"Vulnerability {vulnerability_id} has no description."}

        if not vulnerability.affected_products:
            return {"error": f"Vulnerability {vulnerability_id} has no affected products."}

        if len(vulnerability.affected_products) == 1:
            return vulnerability.affected_products[0]

        # TODO: consider adding a port for extracting terms from the description into a structured format
        terms = vulnerability.description.lower().split()
        products_by_score = {}

        for product in vulnerability.affected_products:
            if product.name not in products_by_score:
                products_by_score[product.name] = {
                    'score': PRODUCT_PART_SCORES[product.part], 'product': product
                }

            # TODO: The product_type should be provided before, classifier should be used before in a preceding service
            product_type = self.product_classifier_port.classify_product_by_type(product)

            # TODO: consider also the weakness type in combination with the product type to determine the score
            products_by_score[product.name]['score'] += PRODUCT_TYPE_SCORES[product_type]

            # TODO: Implement other ways to match the product name with the vulnerability description.
            for term in terms:
                if term in product.name.lower():
                    products_by_score[product.name]['score'] += 1

        selection = max(products_by_score, key=lambda x: products_by_score[x]['score'])

        return products_by_score[selection]['product']
