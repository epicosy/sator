from cement import App, TestApp
from cement.core.exc import CaughtSignal
from .exc import SatorError
from .controllers.base import Base
from .controllers.analysis import Analyze
from .controllers.extraction import Extract
from .controllers.resolution import Resolve
from .controllers.annotation import Annotate
from .bootstrap import (create_product_resolution, create_vulnerability_resolution, create_product_annotation,
                        create_diff_resolution, create_diff_annotation, create_diff_analysis, create_details_extractor,
                        create_details_annotation)


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
            Base, Resolve, Annotate, Analyze, Extract
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
        # TODO: find a way to do this in a more elegant way, it is getting out of hand
        product_resolution = create_product_resolution(app.config)
        vulnerability_resolution = create_vulnerability_resolution(app.config)
        diff_resolution = create_diff_resolution(app.config)
        product_annotation = create_product_annotation(app.config)
        diff_annotation = create_diff_annotation(app.config)
        details_annotation = create_details_annotation(app.config)
        diff_analysis = create_diff_analysis(app.config)
        details_extraction = create_details_extractor(app.config)
        # TODO: find a way to pass these to the Resolve controller
        app.diff_resolution = diff_resolution
        app.product_resolution = product_resolution
        app.vulnerability_resolution = vulnerability_resolution
        app.product_annotation = product_annotation
        app.diff_annotation = diff_annotation
        app.details_annotation = details_annotation
        app.diff_analysis = diff_analysis
        app.details_extraction = details_extraction

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
