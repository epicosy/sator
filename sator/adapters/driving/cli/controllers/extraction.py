from cement import Controller, ex


class Extract(Controller):
    class Meta:
        label = 'extract'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator extract'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def details(self):
        details = self.app.details_extraction.extract_details(self.app.pargs.vulnerability_id)

        print(details)
