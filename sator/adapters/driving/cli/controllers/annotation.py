from cement import Controller, ex

from sator.core.use_cases.annotation.product import ProductAnnotation

from sator.adapters.driven.persistence.json import JsonPersistence
from sator.adapters.driven.repositories.product.cpe import CPEDictionary
from sator.adapters.driven.classifiers.product.keyword_based import KeywordBasedProductClassifier


class Annotate(Controller):
    class Meta:
        label = 'annotate'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator annotate'

        # TODO: should come from some configuration
        arguments = [
            (['-pp', '--persistence_path'], {'help': 'persistence path', 'type': str, 'required': True}),
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-cpe', '--cpe_path'], {'help': 'path for cpe data', 'type': str, 'required': False}),
            (['-vn', '--vendor_name'], {'help': 'vendor name', 'type': str, 'required': True}),
            (['-pn', '--product_name'], {'help': 'product name', 'type': str, 'required': True})
        ]
    )
    def product(self):
        product_annotation = ProductAnnotation(
            product_classifier_port=KeywordBasedProductClassifier(),
            product_reference_port=CPEDictionary(self.app.pargs.cpe_path),
            storage_port=JsonPersistence(self.app.pargs.persistence_path)
        )

        product_descriptor = product_annotation.annotate_product(
            self.app.pargs.vendor_name, self.app.pargs.product_name
        )

        print(product_descriptor)
