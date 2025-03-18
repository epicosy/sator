from cement import App, TestApp
from cement.core.exc import CaughtSignal
from .exc import SatorError
from .controllers.base import Base
from .controllers.process import Process
from .controllers.analysis import Analyze
from .controllers.extraction import Extract
from .controllers.resolution import Resolve
from .controllers.annotation import Annotate
from sator_app.services.processing.vulnerability import VulnerabilityProcessingService
from .bootstrap import (create_resolution_builder, create_extraction_builder, create_annotation_builder,
                        create_analysis_builder)


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

        interfaces = []

        # register handlers
        handlers = [
            Base, Resolve, Annotate, Analyze, Extract, Process
        ]

    def get_config(self, key: str):
        if self.config.has_section(self.Meta.label):
            if key in self.config.keys(self.Meta.label):
                return self.config.get(self.Meta.label, key)

        return None


class SatorTest(TestApp, Sator):
    """A sub-class of Sator that is better suited for testing."""

    class Meta:
        label = 'sator'


def main():
    with Sator() as app:
        app.resolution_builder = create_resolution_builder(app.config)
        app.extraction_builder = create_extraction_builder(app.config)
        app.annotation_builder = create_annotation_builder(app.config)
        app.analysis_builder = create_analysis_builder(app.config)
        app.vulnerability_processing = VulnerabilityProcessingService(
            app.annotation_builder.create_vulnerability_attributes_annotation(),
            app.extraction_builder.create_vulnerability_attributes_extraction(),
            app.analysis_builder.create_vulnerability_attributes_analysis(),
            app.resolution_builder.create_vulnerability_metadata_resolution(),
            app.resolution_builder.create_vulnerability_references_resolution()
        )

        try:
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
