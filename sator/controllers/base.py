from cement import Controller, ex

from sator import __version__
from sator.core.exc import SatorError

VERSION_BANNER = """ vulnerability database api (v%s)""" % __version__


class Base(Controller):
    class Meta:
        label = 'base'

        # text displayed at the top of --help output
        description = 'vulnerability database api'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator run'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER}),
            (['-u', '--uri'], {'help': 'URI for database. (Overwrites config uri)', 'type': str, 'required': False})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    def _set_database_uri(self):
        _uri = self.app.flask_configs.get('SQLALCHEMY_DATABASE_URI', None)

        if self.app.pargs.uri:
            if _uri:
                self.app.log.info(f"Overwriting config database uri")
            self.app.flask_configs['SQLALCHEMY_DATABASE_URI'] = self.app.pargs.uri
        elif _uri is None:
            raise SatorError("No database URI specified")

    def _post_argument_parsing(self):
        super()._post_argument_parsing()
        self._set_database_uri()

    def _default(self):
        """Default action if no sub-command is passed."""

        self.app.args.print_help()

    @ex(
        help='Generates with OpenAI API the software type for each repository in the database',
        arguments=[
            (['-gt', '--tokens'], {'help': 'Comma-separated list of tokens for the GitHub API.', 'type': str,
                                   'required': True}),
            (['-ot', '--openai-token'], {'help': 'Token for the OpenAI API.', 'type': str, 'required': True}),
            (['-m', '--model'], {'help': 'Model to use for the OpenAI API.', 'type': str, 'default': 'gpt-3.5-turbo'}),
        ])
    def generate(self):
        """Generate sub-command."""
        self.app.handler.get('handlers', 'openai', setup=True).generate()

