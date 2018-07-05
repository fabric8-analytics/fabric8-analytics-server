"""Default configuration for all server subsystems and interfaces (databases...)."""

import os

from f8a_worker.utils import json_serial
from f8a_worker.defaults import configuration as worker_configuration

# Disable CDN support to mitigate potential risks connected to it
BOOTSTRAP_SERVE_LOCAL = True

DEBUG = os.getenv('F8A_DEBUG', False)

# DB Settings
SQLALCHEMY_DATABASE_URI = worker_configuration.POSTGRES_CONNECTION

# Don't attach custom messages to 404 errors with flask-restful
ERROR_404_HELP = False

JSONIFY_PRETTYPRINT_REGULAR = True
RESTFUL_JSON = {'default': json_serial, 'indent': 4, 'separators': (',', ': ')}

# Don't do this in production!
SECRET_KEY = 'devkey'
# length of token life in seconds
API_TOKEN_LIFETIME = 3600

# license synonyms
# /<url>/<org>/<repo>/<branch>/<dir/file>
LIC_SYNONYMS_URL = '/'.join(['https://raw.githubusercontent.com', 'fabric8-analytics',
                             'fabric8-analytics-license-analysis', 'master',
                             'tests/synonyms/license_synonyms.json'])


# Info about deployed version
SYSTEM_VERSION = os.getenv('F8A_SYSTEM_VERSION', default='/etc/coreapi-release')

BAYESIAN_ANALYTICS_URL = os.getenv('BAYESIAN_ANALYTICS_URL',
                                   'http://recommendationapi-server:5000')
GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
                           host=worker_configuration.BAYESIAN_GREMLIN_HTTP_SERVICE_HOST,
                           port=worker_configuration.BAYESIAN_GREMLIN_HTTP_SERVICE_PORT)
BAYESIAN_FETCH_PUBLIC_KEY = os.getenv('BAYESIAN_FETCH_PUBLIC_KEY', None)
BAYESIAN_PUBLIC_KEY = os.getenv('BAYESIAN_AUTH_KEY', '')
BAYESIAN_JWT_AUDIENCE = os.getenv('BAYESIAN_JWT_AUDIENCE', None)
BAYESIAN_COMPONENT_TAGGED_COUNT = os.getenv('BAYESIAN_COMPONENT_TAGGED_COUNT', 2)

F8_API_BACKBONE_HOST = os.getenv('F8_API_BACKBONE_HOST', 'http://f8a-server-backbone')
AUTH_URL = os.getenv('AUTH_URL', 'https://auth.openshift.io')
CORE_DEPENDENCIES_REPO_URL = os.getenv('CORE_DEPENDENCIES_REPO', 'https://github.com/'
                                                                 'fabric8-analytics/'
                                                                 'booster-core-dependencies')

GEMINI_SERVER_URL = "http://{host}:{port}".format(
                     host=os.getenv('F8A_GEMINI_SERVER_SERVICE_HOST'),
                     port=os.getenv('F8A_GEMINI_SERVER_SERVICE_PORT'))
