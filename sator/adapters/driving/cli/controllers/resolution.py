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
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True}),
            (['-l', '--locators'], {'help': 'resolve product locators', 'action': 'store_true'})
        ]
    )
    def vulnerability(self):
        if self.app.pargs.locators:
            locators = self.app.vulnerability_resolution.get_locator(self.app.pargs.vuln_id)
            print(f'Locators: {locators}')
        else:
            vulnerability = self.app.vulnerability_resolution.get_vulnerability(self.app.pargs.vuln_id)
            print(f'Vulnerability: {vulnerability}')

    @ex(
        help='Resolves the affected products for the specified vulnerability (already resolved)',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True}),
            (['-l', '--locators'], {'help': 'resolve product locators', 'action': 'store_true'})
        ]
    )
    def products(self):
        if self.app.pargs.locators:
            locators = self.app.product_resolution.get_locators(self.app.pargs.vuln_id)
            print(f'Product Locators: {locators}')
        else:
            affected_products = self.app.vulnerability_resolution.get_affected_products(self.app.pargs.vuln_id)
            print(f'Affected Products: {affected_products}')
