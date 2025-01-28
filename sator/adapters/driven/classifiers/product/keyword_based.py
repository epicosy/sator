from sator.core.models.product import Product
from sator.core.models.enums import ProductType, ProductPart
from sator.core.ports.driven.classifiers.product import ProductClassifierPort


# cms stands for Content Management System;
# nms stands for Network Management System;
# crm stands for Customer Relationship Management;
# jms stands for Java Message Service;
# sdk stands for Software Development Kit;

# ProductType.APPLICATION: ['app', 'client', 'portal', 'suite', 'groupware', 'automation'],
# ProductType.HARDWARE: ['device', 'hardware', 'appliance'],
# ProductType.OPERATING_SYSTEM: ['os', 'runtime'],


PRODUCT_TYPE_BY_KEYWORDS = {
    ProductPart.APPLICATION: {
        ProductType.UTILITY: ['tool', 'utility', 'tools'],
        ProductType.WEB_APPLICATION: ['cms', 'web', 'nms', 'crm', 'jms', 'client', 'portal'],
        ProductType.FRAMEWORK: ['framework', 'sdk', 'engine', 'middleware'],
        ProductType.SERVER: ['server', 'service', 'agent', 'broker'],
        ProductType.LIBRARY: ['lib', 'library', 'package', 'module'],
        ProductType.DATABASE: ['database', 'db'],
        ProductType.PLUGIN: ['plugin', 'extension', 'integration']
    },
    ProductPart.HARDWARE: {
        ProductType.FIRMWARE: ['firmware', 'driver']
    }
}


class KeywordBasedProductClassifier(ProductClassifierPort):
    def classify_product_by_type(self, product: Product) -> ProductType:
        """
            Classify the product by type based on keywords in the product name. Product must have a part.

            Args:
                product: The product to get the type for.

            Returns:
                The type of the product.
        """

        if product.part is None:
            raise ValueError("Product part must be provided to classify the product by type.")

        name = product.name.replace('\\/', '_').replace('-', '_')
        tokens = name.split('_')

        for product_type, keywords in PRODUCT_TYPE_BY_KEYWORDS[product.part]:
            for token in tokens:
                if any(keyword in token for keyword in keywords):
                    return product_type

        return ProductType.UNDEFINED
