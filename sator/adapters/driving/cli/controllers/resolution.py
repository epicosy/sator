from cement import Controller, ex


class Resolve(Controller):
    class Meta:
        label = 'resolve'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator resolve'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vn', '--vendor_name'], {'help': 'product name', 'type': str, 'required': True}),
            (['-pn', '--product_name'], {'help': 'product name', 'type': str, 'required': True}),
        ]
    )
    def product(self):
        # TODO: self.app.product_resolution should probably be a class attribute
        locators = self.app.product_resolution.get_product_locators(
            vendor_name=self.app.pargs.vendor_name, product_name=self.app.pargs.product_name
        )
        print(f'Product Locators: {locators}')

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability(self):
        vulnerability = self.app.vulnerability_resolution.get_vulnerability(self.app.pargs.vuln_id)

        if vulnerability:
            affected_products = self.app.vulnerability_resolution.get_affected_products(vulnerability)
            print(f'Affected Products: {affected_products}')
