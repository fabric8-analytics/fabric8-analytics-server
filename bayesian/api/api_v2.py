# Copyright © 2020 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""Definition of all v2 REST API endpoints of the server module."""

import os
import time
import urllib
import logging

from requests_futures.sessions import FuturesSession
from collections import namedtuple

from flask import Blueprint, request, g
from flask.json import jsonify
from flask_restful import Api, Resource

from f8a_worker.utils import (MavenCoordinates, case_sensitivity_transform)
from fabric8a_auth.auth import login_required
from fabric8a_auth.errors import AuthError
from bayesian.exceptions import HTTPError
from bayesian.utils import (get_system_version,
                            server_create_component_bookkeeping,
                            server_create_analysis,
                            resolved_files_exist,
                            check_for_accepted_ecosystem)
from bayesian.utility.v2.ca_response_builder import ComponentAnalyses
from bayesian.utility.v2.sa_response_builder import StackAnalysesResponseBuilder
from bayesian.utility.v2.stack_analyses import StackAnalyses
from bayesian.utility.db_gateway import RdbAnalyses

errors = {
        'AuthError': {
                         'status': 401,
                         'message': 'Authentication failed',
                         'some_description': 'Authentication failed'
                     }}

api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')
rest_api_v2 = Api(api_v2, errors=errors)


ANALYSIS_ACCESS_COUNT_KEY = 'access_count'
TOTAL_COUNT_KEY = 'total_count'

ANALYTICS_API_VERSION = "v2.0"
HOSTNAME = os.environ.get('HOSTNAME', 'bayesian-api')
METRICS_SERVICE_URL = "http://{}:{}".format(
    os.environ.get('METRICS_ACCUMULATOR_HOST', 'metrics-accumulator'),
    os.environ.get('METRICS_ACCUMULATOR_PORT', '5200')
)

worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)
_resource_paths = []
logger = logging.getLogger(__file__)


@api_v2.route('/readiness')
def readiness():
    """Handle the /readiness REST API call."""
    return jsonify({}), 200


@api_v2.route('/liveness')
def liveness():
    """Handle the /liveness REST API call."""
    return jsonify({}), 200


class ApiEndpoints(Resource):
    """Implementation of / REST API call."""

    @staticmethod
    def get():
        """Handle the GET REST API call."""
        return {'paths': sorted(_resource_paths)}


class SystemVersion(Resource):
    """Implementation of /system/version REST API call."""

    @staticmethod
    def get():
        """Handle the GET REST API call."""
        return get_system_version()


class ComponentAnalysesApi(Resource):
    """Implementation of all /component-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def get(ecosystem, package, version):
        """Handle the GET REST API call.

        Component Analyses:
            - If package is Known (exists in GraphDB (Snyk Edge) returns Json formatted response.
            - If package is not Known:
                - INVOKE_API_WORKERS flag is up: Trigger bayesianApiFlow to fetch Package details
                - INVOKE_API_WORKERS flag is down: Trigger bayesianFlow to fetch Package details

        :return:
            JSON Response
        """
        st = time.time()
        # Analytics Data
        metrics_payload = {
            "pid": os.getpid(),
            "hostname": HOSTNAME,
            "endpoint": request.endpoint,
            "request_method": "GET",
            "ecosystem": ecosystem,
            "package": package,
            "version": version
        }
        response_template = namedtuple("response_template", ["message", "status"])
        logger.info("Executed v2 API")
        package = urllib.parse.unquote(package)
        if not check_for_accepted_ecosystem(ecosystem):
            msg = f"Ecosystem {ecosystem} is not supported for this request"
            raise HTTPError(400, msg)
        if ecosystem == 'maven':
            try:
                package = MavenCoordinates.normalize_str(package)
            except ValueError:
                msg = f"Invalid maven format - {package}"
                metrics_payload.update({"status_code": 400, "value": time.time() - st})
                _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)
                raise HTTPError(400, msg)
        package = case_sensitivity_transform(ecosystem, package)

        # Perform Component Analyses on Vendor specific Graph Edge.
        analyses_result = ComponentAnalyses(
            ecosystem, package, version).get_component_analyses_response()

        if analyses_result is not None:
            # Known component for Fabric8 Analytics
            server_create_component_bookkeeping(ecosystem, package, version, g.decoded_token)

            metrics_payload.update({"status_code": 200, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)
            return analyses_result

        if os.environ.get("INVOKE_API_WORKERS", "") == "1":
            # Trigger the unknown component ingestion.
            server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                   api_flow=True, force=False, force_graph_sync=True)
            msg = f"Package {ecosystem}/{package}/{version} is unavailable. " \
                  "The package will be available shortly," \
                  " please retry after some time."

            metrics_payload.update({"status_code": 202, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)

            return response_template({'error': msg}, 202)

        # No data has been found and INVOKE_API_WORKERS flag is down.
        server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                               api_flow=False, force=False, force_graph_sync=True)
        msg = f"No data found for {ecosystem} package {package}/{version}"

        metrics_payload.update({"status_code": 404, "value": time.time() - st})
        _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)

        raise HTTPError(404, msg)


class StackAnalysesApi(Resource):
    """Implements stack analysis REST APIs.

    Implements /api/v2/stack-analyses REST APIs for POST and GET calls.
    """

    method_decorators = [login_required]

    @staticmethod
    def get(external_request_id):
        """Handle /api/v2/stack-analyses GET REST API."""
        logger.debug("GET request_id: {}".format(external_request_id))

        # 1. Assemble final GET response and return
        sa_response_builder = StackAnalysesResponseBuilder(external_request_id,
                                                           RdbAnalyses(external_request_id))

        # 2. If there was no exception raise, means request is ready to be served.
        return sa_response_builder.get_response()

    @staticmethod
    def post():
        """Handle /api/v2/stack-analyses POST REST API."""
        # 1. Read mandatory params
        manifest = request.files.get('manifest') or None
        file_path = request.form.get('file_path') or None
        ecosystem = request.form.get('ecosystem') or None

        logger.debug('Mandatory params :: manifest: {} file_path: {} ecosystem: {}'.format(
            manifest, file_path, ecosystem))

        # 2. Read optional params and set default value as per V2 spec.
        show_transitive = request.form.get('show_transitive') or 'true'

        logger.info('Optional params :: show_transitive: {}'.format(show_transitive))

        # 3. Validate post params.
        # Manifest is mandatory and must be a string.
        if manifest is None or not resolved_files_exist(manifest.filename):
            error_message = 'Error processing request. Manifest is missing its value {} is ' \
                            'invalid / not supported'.format(manifest)
            logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # File path is mandatory and must be a string.
        if file_path is None or not isinstance(file_path, str):
            error_message = 'Error processing request. File path is missing / its value ' \
                            '{} is invalid'.format(file_path)
            logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Ecosystem  is mandatory and must be a string.
        if ecosystem is None or not isinstance(ecosystem, str):
            error_message = 'Error processing request. Ecosystem is missing / its value {} ' \
                            'is invalid'.format(ecosystem)
            logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Ecosystem should be a valid value
        if not check_for_accepted_ecosystem(ecosystem):
            error_message = 'Error processing request. {} ecosystem is not supported'.format(
                ecosystem)
            logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # 4. Build manifest info from manifest file and path. It read content in utf-8 encoding.
        manifest_file_info = {
            'filename': manifest.filename,
            'filepath': file_path,
            'content': manifest.read().decode('utf-8')
        }
        logger.info(manifest_file_info)

        # 5. Initiate stack analyses object
        sa = StackAnalyses(None, ecosystem, manifest_file_info, show_transitive)

        # 6. Post request
        return sa.post_request()


@api_v2.route('/_error')
def error():
    """Implement the endpoint used by httpd, which redirects its errors to it."""
    try:
        status = int(os.getenv("REDIRECT_STATUS"))
    except Exception:
        # if there's an exception, it means that a client accessed this directly;
        #  in this case, we want to make it look like the endpoint is not here
        return api_404_handler()
    msg = 'Unknown error'
    if status == 401:
        msg = 'Authentication failed'
        raise AuthError(status, msg)
    elif status == 405:
        msg = 'Method not allowed for this endpoint'
    raise HTTPError(status, msg)


# flask-restful doesn't actually store a list of endpoints, so we register them as they
#  pass through add_resource_no_matter_slashes


def add_resource_no_matter_slashes(resource, route, endpoint=None, defaults=None):
    """Add a resource for both trailing slash and no trailing slash to prevent redirects."""
    slashless = route.rstrip('/')
    _resource_paths.append(api_v2.url_prefix + slashless)
    slashful = route + '/'
    endpoint = endpoint or resource.__name__.lower()
    defaults = defaults or {}

    # resources with and without slashes
    rest_api_v2.add_resource(resource,
                             slashless,
                             endpoint=endpoint + '__slashless',
                             defaults=defaults)
    rest_api_v2.add_resource(resource,
                             slashful,
                             endpoint=endpoint + '__slashful',
                             defaults=defaults)


add_resource_no_matter_slashes(ApiEndpoints, '')
add_resource_no_matter_slashes(SystemVersion, '/system/version')

# Component analyses routes
add_resource_no_matter_slashes(ComponentAnalysesApi,
                               '/component-analyses/<ecosystem>/<package>/<version>',
                               endpoint='get_component_analysis')

# Stack analyses routes
add_resource_no_matter_slashes(StackAnalysesApi,
                               '/stack-analyses',
                               endpoint='post_stack_analyses')
add_resource_no_matter_slashes(StackAnalysesApi,
                               '/stack-analyses/<external_request_id>',
                               endpoint='get_stack_analyses')


# ERROR HANDLING
@api_v2.errorhandler(HTTPError)
def handle_http_error(err):
    """Handle HTTPError exceptions."""
    try:
        return jsonify({'error': err.error}), err.status_code
    except AttributeError:
        return jsonify({'error': err.data.get('error')}), err.code


@api_v2.errorhandler(AuthError)
def api_401_handler(err):
    """Handle AuthError exceptions."""
    return jsonify(error=err.error), err.status_code


# workaround https://github.com/mitsuhiko/flask/issues/1498
# NOTE: this *must* come in the end, unless it'll overwrite rules defined
# after this
@api_v2.route('/<path:invalid_path>')
def api_404_handler():
    """Handle all other routes not defined above."""
    return jsonify(error='Cannot match given query to any API v2 endpoint'), 404
