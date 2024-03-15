from cement import Controller, ex

from sator import __version__

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
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER})
        ]

    def __init__(self, **kw):
        super().__init__(**kw)

    def _post_argument_parsing(self):
        super()._post_argument_parsing()

    def _default(self):
        """Default action if no sub-command is passed."""

        self.app.args.print_help()
