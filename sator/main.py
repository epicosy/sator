from cement import App, TestApp
from cement.core.exc import CaughtSignal
from .core.exc import SatorError
from .controllers.base import Base
from .controllers.database import Database
from .controllers.server import Server
from .controllers.source import Source
from pathlib import Path
from sator.handlers.multi_task import MultiTaskHandler
from sator.handlers.nvd import NVDHandler
from sator.core.interfaces import HandlersInterface
from sator.handlers.github import GithubHandler
from sator.handlers.openai import OpenAIHandler


class Sator(App):
    """vulnerability database primary application."""

    class Meta:
        label = 'sator'

        # call sys.exit() on close
        exit_on_close = True

        # load additional framework extensions
        extensions = [
            'yaml',
            'colorlog',
            'jinja2',
        ]

        # configuration handler
        config_handler = 'yaml'

        # configuration file suffix
        config_file_suffix = '.yml'

        # set the log handler
        log_handler = 'colorlog'

        # set the output handler
        output_handler = 'jinja2'

        interfaces = [
            HandlersInterface
        ]

        # register handlers
        handlers = [
            Base, Database, Server, Source, MultiTaskHandler, NVDHandler, GithubHandler, OpenAIHandler
        ]

    def get_config(self, key: str):
        if self.config.has_section(self.Meta.label):
            if key in self.config.keys(self.Meta.label):
                return self.config.get(self.Meta.label, key)

        return None

    def setup_working_dir(self):
        if 'working_dir' in self.config.keys('sator'):
            working_dir = Path(self.config.get('sator', 'working_dir')).expanduser()
        else:
            working_dir = Path.home().parent / 'sator'

            if not working_dir.exists():
                self.log.warning(f"Working directory not found in config file. Using default path: {working_dir}")

        working_dir.mkdir(exist_ok=True, parents=True)
        self.extend('working_dir', working_dir)

    def set_flask_configs(self):
        _flask_configs = {k.upper(): v for k, v in self.config.get_dict()['flask'].items()}
        self.extend('flask_configs', _flask_configs)


class SatorTest(TestApp, Sator):
    """A sub-class of Sator that is better suited for testing."""

    class Meta:
        label = 'sator'


def main():
    with Sator() as app:
        try:
            app.setup_working_dir()
            app.set_flask_configs()
            app.run()

        except AssertionError as e:
            print('AssertionError > %s' % e.args[0])
            app.exit_code = 1

            if app.debug is True:
                import traceback
                traceback.print_exc()

        except SatorError as e:
            print('SatorError > %s' % e.args[0])
            app.exit_code = 1

            if app.debug is True:
                import traceback
                traceback.print_exc()

        except CaughtSignal as e:
            # Default Cement signals are SIGINT and SIGTERM, exit 0 (non-error)
            print('\n%s' % e)
            app.exit_code = 0


if __name__ == '__main__':
    main()
