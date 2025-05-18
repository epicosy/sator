from sator_core.models.product import Product, ProductAttributes, ProductReferences
from sator_core.ports.driven.extraction.attributes.product import ProductAttributesExtractorPort


class KeywordBasedProductAttributesExtractor(ProductAttributesExtractorPort):
    def extract_product_attributes(self, product: Product, references: ProductReferences) -> ProductAttributes | None:

        # TODO: Implement the logic to extract attributes based on keywords
        return ProductAttributes(
            product=product
        )
