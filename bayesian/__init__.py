import logging

from flask import Flask
from flask import Response
from flask import g
from flask import redirect
from flask import request
from flask import url_for
from flask_appconfig import AppConfig
from flask_security import SQLAlchemyUserDatastore, Security
from flask_sqlalchemy import SQLAlchemy


def setup_logging(app):
    if not app.debug:
        handler = logging.StreamHandler()
        handler.setLevel(logging.WARNING)
        app.logger.addHandler(handler)


# we must initialize DB here to not create import loop with .auth...
#  flask really sucks at this
rdb = SQLAlchemy()


def create_app(configfile=None):
    # do the imports here to not shadow e.g. "import bayesian.frontend.api_v1"
    # by Blueprint imported here
    from .api_v1 import api_v1
    from .exceptions import HTTPError
    from .utils import JSONEncoderWithExtraTypes
    app = Flask(__name__)

    AppConfig(app, configfile)

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

    @app.errorhandler(HTTPError)
    def handleerrors(e):
        bp = app.blueprints.get(request.blueprint)
        # if there's an error pre-request (e.g. during authentication) in non-GET requests,
        #  request.blueprint is not set yet
        if not bp:
            # sort by the length of url_prefix, filter out blueprints without prefix
            bps = reversed(sorted(
                [(name, b) for name, b in app.blueprints.items() if b.url_prefix is not None],
                key=lambda tpl: len(tpl[1].url_prefix)))
            for bp_name, b in bps:
                if request.environ['PATH_INFO'].startswith(b.url_prefix):
                    bp = b
                    break
        if bp:
            handler = getattr(bp, 'coreapi_http_error_handler', None)
            if handler:
                return handler(e)
        return Response(e.error, status=e.status_code)

    setup_logging(app)

    @app.before_request
    def set_current_user():
        g.current_user = None

    return app


app = create_app()
