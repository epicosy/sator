from cement import Controller, ex


class Orchestration(Controller):
    class Meta:
        label = 'orchestrate'
        stacked_on = 'base'
        stacked_type = 'nested'
        epilog = 'Usage: sator orchestrate'
        arguments = []

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Orchestrates the complete analysis workflow for a given vulnerability.',
        arguments=[
            (['-vid', '--vulnerability_id'], {'help': 'vulnerability id', 'type': str, 'required': True})
        ]
    )
    def processing(self):
        results = self.app.processing_orchestration.orchestrate_analysis(self.app.pargs.vulnerability_id)
        print(results)
