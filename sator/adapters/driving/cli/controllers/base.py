from cement import Controller, ex

from sator.adapters.driving.cli import __version__

APP_DESCRIPTION = "OSS Vulnerability Analysis Application CLI"
VERSION_BANNER = f"{APP_DESCRIPTION} (v{__version__})"


class Base(Controller):
    class Meta:
        label = 'base'

        # text displayed at the top of --help output
        description = APP_DESCRIPTION

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator run'

        # controller level arguments. ex: 'sator --version'
        arguments = [
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    def _default(self):
        """Default action if no sub-command is passed."""

        self.app.args.print_help()
