from cement import Controller, ex

from sator import create_flask_app
from sator.utils.misc import get_allowed_origins


class Server(Controller):
    class Meta:
        label = 'server'
        stacked_on = 'base'
        stacked_type = 'nested'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator server'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-p', '--port'], {'help': 'Port for server. (Overwrites config port)', 'type': int, 'required': False}),
            (['-a', '--address'], {'help': 'IPv4 host address for server. ', 'type': str, 'default': 'localhost'}),
            (['-d', '--debug'], {'help': 'Debug mode for server. (Overwrites config debug)', 'type': bool,
                                 'required': False}),
            (['-k', '--key'], {'help': 'Secret Key for server. (Overwrites config key)', 'type': str,
                               'required': False})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    def _set_port(self):
        _port = self.app.flask_configs.get('RUN_PORT', None)

        if self.app.pargs.port:
            if _port:
                self.app.log.info(f"Overwriting config port number from {_port} to '{self.app.pargs.port}'")
            self.app.flask_configs['RUN_PORT'] = self.app.pargs.port
        elif _port is None:
            self.app.log.info("No port number specified, setting default port number to '3000'")
            self.app.flask_configs['RUN_PORT'] = 3000

    def _set_debug(self):
        _debug = self.app.flask_configs.get('DEBUG', False)

        if self.app.pargs.debug:
            if _debug:
                self.app.log.info(f"Overwriting config debug mode from {_debug} to '{self.app.pargs.debug}'")
            self.app.flask_configs['DEBUG'] = self.app.pargs.debug
        else:
            self.app.flask_configs['DEBUG'] = _debug

    def _set_secret_key(self):
        _key = self.app.flask_configs.get('SECRET_KEY', None)

        if self.app.pargs.key:
            if _key:
                self.app.log.info(f"Overwriting config secret key")
            self.app.flask_configs['SECRET_KEY'] = self.app.pargs.key
        elif _key is None:
            import secrets
            self.app.log.info("No secret key specified, generating one")
            self.app.flask_configs['SECRET_KEY'] = secrets.token_hex()

    def _post_argument_parsing(self):
        super()._post_argument_parsing()

        if self.app.pargs.__controller_namespace__ == 'server':
            self._set_port()
            self._set_debug()
            self._set_secret_key()

            allowed_origins = get_allowed_origins()
            allowed_origins.append(f"http://{self.app.pargs.address}:*")
            self.app.log.info(f"Allowed origins: {allowed_origins}")
            flask_app = create_flask_app(configs=self.app.flask_configs, allowed_origins=allowed_origins)

            with flask_app.app_context():
                from sator.core.models import db, shutdown_session
                db.init_app(flask_app)
                flask_app.teardown_appcontext(shutdown_session)

            self.app.extend('flask_app', flask_app)

    @ex(
        help='Launches the server API'
    )
    def run(self):
        """Run sub-command."""

        self.app.flask_app.run(debug=self.app.flask_configs['DEBUG'], port=self.app.flask_configs['RUN_PORT'],
                               host=self.app.pargs.address)
