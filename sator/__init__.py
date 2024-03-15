import pkg_resources

__version__ = pkg_resources.get_distribution('sator').version

from flask import Flask
from flask_graphql import GraphQLView
from flask_cors import CORS
from sator.core.graphql.schema import schema


def create_flask_app(configs: dict, allowed_origins: list = None):
    flask_app = Flask(__name__)

    CORS(flask_app, resources={r"/graphql/*": {"origins": allowed_origins if allowed_origins else []}})

    flask_app.config.update(configs)

    @flask_app.route("/")
    def index():
        return f"Sator ({__version__}) API"

    flask_app.add_url_rule(
        '/graphql',
        view_func=GraphQLView.as_view(
            'graphql',
            schema=schema,
            graphiql=True
        )
    )

    return flask_app
