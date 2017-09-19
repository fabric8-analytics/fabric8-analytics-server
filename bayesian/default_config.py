import os

from f8a_worker.utils import json_serial


# Disable CDN support to mitigate potential risks connected to it
BOOTSTRAP_SERVE_LOCAL = True

DEBUG = os.getenv('F8A_DEBUG', False)

# DB Settings
SQLALCHEMY_DATABASE_URI = os.getenv('F8A_POSTGRES',
                                    default='postgres://coreapi:coreapi@localhost:5432/coreapi')

# Don't attach custom messages to 404 errors with flask-restful
ERROR_404_HELP = False

JSONIFY_PRETTYPRINT_REGULAR = True
RESTFUL_JSON = {'default': json_serial, 'indent': 4, 'separators': (',', ': ')}

# Don't do this in production!
SECRET_KEY = 'devkey'
# length of token life in seconds
API_TOKEN_LIFETIME = 3600

# Info about deployed version
SYSTEM_VERSION = os.getenv('F8A_SYSTEM_VERSION', default='/etc/coreapi-release')

BAYESIAN_ANALYTICS_URL = os.getenv('BAYESIAN_ANALYTICS_URL',
                                   'http://recommendationapi-server:5000')
GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
                           host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
                           port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
BAYESIAN_FETCH_PUBLIC_KEY = os.getenv('BAYESIAN_FETCH_PUBLIC_KEY', None)
BAYESIAN_PUBLIC_KEY = os.getenv('BAYESIAN_AUTH_KEY', '')
BAYESIAN_JWT_AUDIENCE = os.getenv('BAYESIAN_JWT_AUDIENCE', None)
