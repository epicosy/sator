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
