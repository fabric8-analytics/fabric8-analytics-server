"""Module with the declaration of web application and its basic endpoints."""

import logging
import os

from flask import Flask
from flask import g
from flask import redirect
from flask import url_for
from flask_appconfig import AppConfig
from flask_sqlalchemy import SQLAlchemy
from flask_cache import Cache
from raven.contrib.flask import Sentry

from f8a_worker.setup_celery import init_selinon

from prometheus_client import multiprocess
from prometheus_client.core import CollectorRegistry
from prometheus_flask_exporter import PrometheusMetrics


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

# Add Prometheus Metrics Support
registry = CollectorRegistry()
prometheus_multiproc_dir = os.environ.get('PROMETHEUS_LOG_DIR')
multiprocess.MultiProcessCollector(registry, path=prometheus_multiproc_dir)

metrics = PrometheusMetrics(app=None, registry=registry, buckets=(1.0, 2.0, 3.0, 4.0, 5.0, 8.0,
                                                                  13.0, 21.0, 34.0, float("inf")))


def create_app(configfile=None):
    """Create the web application and define basic endpoints."""
    # do the imports here to not shadow e.g. "import bayesian.frontend.api_v1"
    # by Blueprint imported here
    from .api_v1 import api_v1
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

    metrics.init_app(app)
    app.logger.info("************ Metrics Initialized *****************")

    return app


init_selinon()

app = create_app()

SENTRY_DSN = os.environ.get("SENTRY_DSN", "")
sentry = Sentry(app, dsn=SENTRY_DSN, logging=True, level=logging.ERROR)

app.logger.info('App initialized, ready to roll...')
