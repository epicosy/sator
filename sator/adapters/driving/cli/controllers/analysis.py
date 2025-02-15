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
        help='Gets data from the specified source',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def diff(self):
        bug_location = self.app.diff_analysis.analyze_diff(self.app.pargs.vulnerability_id)

        print(bug_location)
