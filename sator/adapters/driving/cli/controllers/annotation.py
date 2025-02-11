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
        help='Gets data from the specified source',
        arguments=[
            (['-vn', '--vendor_name'], {'help': 'vendor name', 'type': str, 'required': True}),
            (['-pn', '--product_name'], {'help': 'product name', 'type': str, 'required': True})
        ]
    )
    def product(self):
        product_descriptor = self.app.product_annotation.annotate_product(
            self.app.pargs.vendor_name, self.app.pargs.product_name
        )

        print(product_descriptor)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def diff(self):
        diff_annotation = self.app.diff_annotation.annotate_diff(self.app.pargs.vulnerability_id)

        print(diff_annotation)
