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

    def _post_argument_parsing(self):
        super()._post_argument_parsing()

        if self.app.pargs.__controller_namespace__ == 'source':
            from sator.core.models import set_db
            set_db(self.app.flask_configs.get('SQLALCHEMY_DATABASE_URI'))

    @ex(
        help='Gets data from the specified source'
    )
    def collect(self):
        self.app.handler.get('handlers', self.app.pargs.name, setup=True).run()

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
