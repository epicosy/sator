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
        help='Resolves the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability(self):
        vulnerability = self.app.vulnerability_resolution.get_vulnerability(self.app.pargs.vuln_id)
        print(f'Vulnerability: {vulnerability}')

    @ex(
        help='Resolves the affected products for the specified vulnerability (already resolved)',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def products(self):
        affected_products = self.app.vulnerability_resolution.get_affected_products(self.app.pargs.vuln_id)
        print(f'Affected Products: {affected_products}')

    @ex(
        help='Resolves the product locators for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def locators(self):
        # TODO: self.app.product_resolution should probably be a class attribute
        locators = self.app.product_resolution.get_product_locators(self.app.pargs.vuln_id)
        print(f'Product Locators: {locators}')
