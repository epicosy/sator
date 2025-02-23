from cement import Controller, ex


class Analyze(Controller):
    class Meta:
        label = 'analyze'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator analyze'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Analyzes the patch attributes of the specified vulnerability and outputs the patch locator',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def patch_attributes(self):
        patch_locator = self.app.patch_attributes_analysis.analyze_patch_attributes(self.app.pargs.vulnerability_id)

        print(patch_locator)

    @ex(
        help='Analyzes the attributes of the specified vulnerability and outputs the vulnerability locator',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability_attributes(self):
        vuln_locator = self.app.vulnerability_attributes_analysis.analyze_vulnerability_attributes(
            self.app.pargs.vulnerability_id
        )

        print(vuln_locator)

    @ex(
        help='Analyzes the attributes of the specified product and outputs the product locator',
        arguments=[
            (['-pid', '--product_id'], {'help': 'product id', 'type': str, 'required': True})
        ]
    )
    def product_attributes(self):
        product_locator = self.app.product_attributes_analysis.analyze_product_attributes(self.app.pargs.product_id)

        print(product_locator)
