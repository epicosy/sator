from cement import Controller, ex


class Source(Controller):
    class Meta:
        label = 'source'
        stacked_on = 'base'
        stacked_type = 'nested'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator source'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-n', '--name'], {'help': 'Name of the source. Should map available handlers', 'type': str,
                                'required': True})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Gets data from the specified source',
        arguments=[
            (['-s', '--start'], {'help': 'Start year for the data', 'type': int, 'required': False}),
            (['-e', '--end'], {'help': 'End year for the data', 'type': int, 'required': False})
        ]
    )
    def collect(self):
        from datetime import datetime
        end = datetime.now().year + 1
        start = self.app.pargs.start if self.app.pargs.start else 1988

        if start < 1988:
            self.app.log.error("Start year cannot be less than 1988.")
            return

        if self.app.pargs.end > end:
            self.app.log.error(f"End year cannot be greater than {end}.")
            return
        else:
            end = self.app.pargs.end

        # check if ranges are valid
        if start > end:
            self.app.log.error("Start year cannot be greater than end year.")
            return

        self.app.handler.get('handlers', self.app.pargs.name, setup=True).run(start=start, end=end)

    @ex(
        help='Gets data from GitHub',
        arguments=[
            (['-gt', '--tokens'], {'help': 'Comma-separated list of tokens for the GitHub API.', 'type': str,
                                   'required': True}),
        ]
    )
    def metadata(self):
        """Metadata sub-command."""
        self.app.handler.get('handlers', self.app.pargs.name, setup=True).add_metadata()
