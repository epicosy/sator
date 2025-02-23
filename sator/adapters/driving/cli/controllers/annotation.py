from cement import Controller, ex


class Annotate(Controller):
    class Meta:
        label = 'annotate'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator annotate'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Annotates a given product',
        arguments=[
            (['-pid', '--product_id'], {'help': 'product id (vendor/name)', 'type': str, 'required': True}),
        ]
    )
    def product_attributes(self):
        prod_descriptor = self.app.product_attributes_annotation.annotate_product_attributes(self.app.pargs.product_id)

        print(prod_descriptor)

    @ex(
        help='Annotates a given diff for a vulnerability',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def patch_attributes(self):
        patch_descriptor = self.app.patch_attributes_annotation.annotate_patch_attributes(
            self.app.pargs.vulnerability_id
        )

        print(patch_descriptor)

    @ex(
        help='Annotates the details of a given vulnerability',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_attributes(self):
        vuln_descriptor = self.app.vulnerability_attributes_annotation.annotate_vulnerability_attributes(
            self.app.pargs.vulnerability_id
        )

        print(vuln_descriptor)
