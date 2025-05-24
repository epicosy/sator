from cement import Controller, ex


class Process(Controller):
    class Meta:
        label = 'process'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator process'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Extracts attributes from the description of the specified vulnerability.',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def vulnerability(self):
        locator = self.app.vulnerability_processing.process_vulnerability(self.app.pargs.vulnerability_id)
        print(locator)


    @ex(
        help='Process the provided product (vendor/name) and finds its source-code.',
        arguments=[
            (['-v', '--vendor'], {'help': 'product vendor', 'type': str, 'required': True}),
            (['-n', '--name'], {'help': 'product name', 'type': str, 'required': True})
        ]
    )
    def product(self):
        locator = self.app.product_processing.process_product(
            vendor=self.app.pargs.vendor,
            name=self.app.pargs.name
        )
        print(locator)

    @ex(
        help='Process the patch for the provided vulnerability (CVE).',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def patch(self):
        locator = self.app.patch_processing.process_patch(
            vulnerability_id=self.app.pargs.vulnerability_id
        )
        print(locator)