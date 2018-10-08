"""Module with the declaration of web application and its basic endpoints."""

import logging
import os

from flask import Flask
from flask import Response
from flask import g
from flask import redirect
from flask import request
from flask import url_for
from flask_appconfig import AppConfig
from flask_sqlalchemy import SQLAlchemy
from flask_cache import Cache

from f8a_worker.setup_celery import init_selinon


def setup_logging(app):
    """Set up logger, the log level is read from the environment variable."""
    if not app.debug:
        handler = logging.StreamHandler()
        log_level = os.environ.get('FLASK_LOGGING_LEVEL', logging.getLevelName(logging.WARNING))
        handler.setLevel(log_level)
        app.logger.addHandler(handler)


# we must initialize DB here to not create import loop with .auth...
#  flask really sucks at this
rdb = SQLAlchemy()
cache = Cache(config={'CACHE_TYPE': 'simple'})


def create_app(configfile=None):
    """Create the web application and define basic endpoints."""
    # do the imports here to not shadow e.g. "import bayesian.frontend.api_v1"
    # by Blueprint imported here
    from .api_v1 import api_v1
    from .exceptions import HTTPError
    from .utils import JSONEncoderWithExtraTypes
    app = Flask(__name__)
    AppConfig(app, configfile)

    cache.init_app(app)

    # actually init the DB with config values now
    rdb.init_app(app)
    app.rdb = rdb

    # We need JSON encoder that can serialize datetime.datetime
    app.json_encoder = JSONEncoderWithExtraTypes

    app.register_blueprint(api_v1)
    # Redirect to latest API version if /api is accessed
    app.route('/api')(lambda: redirect(url_for('api_v1.apiendpoints__slashless')))
    # Likewise for base URL, and make that accessible by name

    @app.route('/')
    def base_url():
        return redirect(url_for('api_v1.apiendpoints__slashless'))

    setup_logging(app)

    @app.before_request
    def set_current_user():
        g.current_user = None

    @app.after_request
    def access_control_allow_origin(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "authorization, content-type"
        response.headers["Access-Control-Allow-Methods"] = "DELETE, GET, HEAD, OPTIONS,"\
            "PATCH, POST, PUT"
        response.headers["Allow"] = "GET, HEAD, OPTIONS, PATCH, POST, PUT"
        return response

    return app


init_selinon()

app = create_app()

app.logger.info('App initialized, ready to roll...')
