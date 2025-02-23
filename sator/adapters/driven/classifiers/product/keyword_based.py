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
    },
    ProductPart.OPERATING_SYSTEM: {
        ProductType.EMBEDDED: ['embedded', 'FreeRTOS', 'VxWorks'],
        ProductType.SERVER: ['server'],
        ProductType.DESKTOP: ['desktop', 'windows', 'mac', 'macOS', 'linux', 'unix'],
        ProductType.MOBILE: ['mobile', 'android', 'ios', 'HarmonyOS', 'KaiOS']
    }
}


class KeywordBasedProductClassifier(ProductClassifierPort):
    def classify_product_by_part(self, product: Product) -> ProductPart:
        # TODO: Implement this method
        return ProductPart.UNDEFINED

    def classify_product_by_type(self, product_name: str, part: ProductPart) -> ProductType:
        """
            Classify the product by type based on keywords in the product name. Product must have a part.

            Args:
                product_name: The name of the product.
                part: The part of the product.

            Returns:
                The type of the product.
        """

        if part is None:
            raise ValueError("Product part must be provided to classify the product by type.")

        name = product_name.replace('\\/', '_').replace('-', '_')
        tokens = name.split('_')

        if part == ProductPart.UNDEFINED:
            # TODO: this should iterate over all keywords and return the first match
            return ProductType.UNDEFINED

        for product_type, keywords in PRODUCT_TYPE_BY_KEYWORDS[part].items():
            for token in tokens:
                if any(keyword.lower() in token.lower() for keyword in keywords):
                    return product_type

        return ProductType.UNDEFINED
