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
        help='Resolves the metadata for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def metadata(self):
        metadata = self.app.vulnerability_resolution.get_metadata(self.app.pargs.vuln_id)
        print(f'Metadata: {metadata}')

    @ex(
        help='Resolves the description for the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def description(self):
        description = self.app.vulnerability_resolution.get_description(self.app.pargs.vuln_id)
        print(f'Description: {description}')

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
            print(locators)
        else:
            affected_products = self.app.vulnerability_resolution.get_affected_products(self.app.pargs.vuln_id)
            print(affected_products)

    @ex(
        help='Resolves the specified vulnerability',
        arguments=[
            (['-vid', '--vuln_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def diff(self):
        diff = self.app.diff_resolution.get_diff(self.app.pargs.vuln_id)
        print(diff)
