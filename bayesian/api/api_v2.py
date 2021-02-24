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
import re
from typing import Dict, Tuple

from requests_futures.sessions import FuturesSession
from collections import namedtuple
from pydantic.error_wrappers import ValidationError

from flask import Blueprint, request
from flask.json import jsonify
from flask_restful import Api, Resource

from f8a_worker.utils import MavenCoordinates, case_sensitivity_transform
from fabric8a_auth.auth import login_required, AuthError
from bayesian.auth import validate_user
from bayesian.exceptions import HTTPError
from bayesian.utility.v2.component_analyses import ca_validate_input, \
    get_known_unknown_pkgs, add_unknown_pkg_info, get_batch_ca_data
from bayesian.utils import (get_system_version,
                            create_component_bookkeeping,
                            check_for_accepted_ecosystem)
from bayesian.utility.v2.ca_response_builder import ComponentAnalyses
from bayesian.utility.v2.sa_response_builder import (StackAnalysesResponseBuilder,
                                                     SARBRequestInvalidException,
                                                     SARBRequestInprogressException,
                                                     SARBRequestTimeoutException)
from bayesian.utility.v2.stack_analyses import StackAnalyses, SAInvalidInputException
from bayesian.utility.v2.sa_models import StackAnalysesPostRequest
from bayesian.utility.v2.backbone_server import BackboneServerException
from bayesian.utility.db_gateway import (RdbAnalyses, RDBSaveException,
                                         RDBInvalidRequestException,
                                         RDBServerException)
from werkzeug.exceptions import BadRequest
from f8a_utils.ingestion_utils import unknown_package_flow
from f8a_utils import ingestion_utils

logger = logging.getLogger(__name__)

errors = {
    'AuthError': {
        'status': 401,
        'error': 'Authentication failed'
    }
}

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
            - If package is not Known: Call Util's function to trigger ingestion flow.

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

        if re.findall('[!@#$%^&*()]', version):
            # Version should not contain special Characters.
            return response_template(
                {'error': "Package version should not have special characters."}, 400)

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

            metrics_payload.update({"status_code": 200, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)
            return analyses_result

        # No data has been found
        unknown_pkgs = set()
        unknown_pkgs.add(ingestion_utils.Package(package=package, version=version))
        unknown_package_flow(ecosystem, unknown_pkgs)

        msg = f"No data found for {ecosystem} package {package}/{version}"

        metrics_payload.update({"status_code": 404, "value": time.time() - st})
        _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)

        raise HTTPError(404, msg)

    @staticmethod
    @validate_user
    def post():
        """Handle the POST REST API call.

        Component Analyses Batch is 4 Step Process:
        1. Gather and clean Request.
        2. Query GraphDB.
        3. Build Stack Recommendation and Build Unknown Packages and Trigger componentApiFlow.
        4. Handle Unknown Packages and Trigger bayesianApiFlow.
        """
        response_template: Tuple = namedtuple("response_template", ["message", "status", "headers"])
        input_json: Dict = request.get_json()
        ecosystem: str = input_json.get('ecosystem')
        user_agent = request.headers.get('User-Agent', None)
        manifest_hash = request.args.get('utm_content', None)
        source = request.args.get('utm_source', None)
        request_id = request.headers.get('request_id', None)
        headers = {"uuid": request.headers.get('uuid', None)}
        try:
            # Step1: Gather and clean Request
            packages_list, normalised_input_pkgs = ca_validate_input(input_json, ecosystem)
            # Step2: Get aggregated CA data from Query GraphDB,
            graph_response = get_batch_ca_data(ecosystem, packages_list)
            # Step3: Build Unknown packages and Generates Stack Recommendation.
            stack_recommendation, unknown_pkgs = get_known_unknown_pkgs(
                ecosystem, graph_response, normalised_input_pkgs)
        except BadRequest as br:
            logger.error(br)
            raise HTTPError(400, str(br)) from br
        except Exception as e:
            msg = "Internal Server Exception. Please contact us if problem persists."
            logger.error(e)
            raise HTTPError(400, msg) from e

        create_component_bookkeeping(ecosystem, packages_list, source, headers.get("uuid"),
                                     user_agent, manifest_hash, request_id)

        # Step4: Handle Unknown Packages
        if unknown_pkgs:
            stack_recommendation = add_unknown_pkg_info(stack_recommendation, unknown_pkgs)
            pkgs_to_ingest = set(map(lambda pkg: ingestion_utils.Package(package=pkg.package,
                                                                         version=pkg.version),
                                     unknown_pkgs))
            logger.debug("Unknown ingestion triggered for %s", pkgs_to_ingest)
            unknown_package_flow(ecosystem, pkgs_to_ingest)

            return response_template(stack_recommendation, 202, headers)
        return response_template(stack_recommendation, 200, headers)


@api_v2.route('/stack-analyses/<external_request_id>', methods=['GET'])
@login_required
@validate_user
def stack_analyses_with_request_id(external_request_id):
    """Handle stack analyses report fetch api."""
    start = time.time()
    logger.debug("[GET] /stack-analyses/%s", external_request_id)

    # 1. Build response builder with id and RDB object.
    sa_response_builder = StackAnalysesResponseBuilder(external_request_id,
                                                       RdbAnalyses(external_request_id))

    # 2. If there was no exception raise, means request is ready to be served.
    try:
        data = sa_response_builder.get_response()
        logger.info('%s took %f seconds for [GET] stack-analyses',
                    external_request_id, time.time() - start)
        return jsonify(data)
    except SARBRequestInvalidException as e:
        raise HTTPError(400, e.args[0]) from e
    except RDBInvalidRequestException as e:
        raise HTTPError(404, e.args[0]) from e
    except RDBServerException as e:
        raise HTTPError(500, e.args[0]) from e
    except SARBRequestInprogressException as e:
        # Avoid HTTPError to ignore sentry reporting for Inprogress request.
        return jsonify({'error': e.args[0]}), 202
    except SARBRequestTimeoutException as e:
        raise HTTPError(408, e.args[0]) from e


@api_v2.route('/stack-analyses', methods=['GET', 'POST'])
@login_required
@validate_user
def stack_analyses():
    """Handle request to trigger a new stack analyses report.

    GET method would raise error to provide missing request id to the user.
    """
    logger.debug('[%s] /stack-analyses accessed', request.method)
    start = time.time()
    if request.method == 'GET':
        raise HTTPError(400, error="Request id missing")

    sa_post_request = None
    try:
        # 1. Validate and build request object.
        sa_post_request = StackAnalysesPostRequest(**request.form, **request.files)

    except ValidationError as e:
        # 2. Check of invalid params and raise exception.
        error_message = 'Validation error(s) in the request.'
        for error in e.errors():
            error_message += ' {}.'.format(error['msg'])
        logger.exception(error_message)
        raise HTTPError(400, error=error_message) from e

    # 3. Initiate stack analyses object
    sa = StackAnalyses(sa_post_request)

    # 4. Post request
    try:
        data = sa.post_request()
        logger.info('%s took %f seconds for [POST] stack-analyses',
                    data['id'], time.time() - start)
        return jsonify(data)
    except SAInvalidInputException as e:
        raise HTTPError(400, e.args[0]) from e
    except BackboneServerException as e:
        raise HTTPError(500, e.args[0])
    except RDBSaveException as e:
        raise HTTPError(500, e.args[0])


@api_v2.route('/_error')
def error():
    """Implement the endpoint used by httpd, which redirects its errors to it."""
    try:
        status = int(os.getenv("REDIRECT_STATUS"))
    except Exception:
        # if there's an exception, it means that a client accessed this directly;
        #  in this case, we want to make it look like the endpoint is not here
        return api_404_handler("/api/v2/")
    msg = 'Unknown error'
    if status == 401:
        msg = 'Authentication failed'
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

add_resource_no_matter_slashes(ComponentAnalysesApi,
                               '/component-analyses/',
                               endpoint='post_component_analysis')


# ERROR HANDLING
@api_v2.errorhandler(HTTPError)
@api_v2.errorhandler(AuthError)
def handle_http_error(err):
    """Handle HTTPError exceptions."""
    try:
        return jsonify({'error': err.error}), err.status_code
    except AttributeError:
        return jsonify({'error': err.data.get('error')}), err.code


# workaround https://github.com/mitsuhiko/flask/issues/1498
# NOTE: this *must* come in the end, unless it'll overwrite rules defined
# after this
@api_v2.route('/<path:invalid_path>')
def api_404_handler(invalid_path):
    """Handle all other routes not defined above."""
    return jsonify(error=f'Cannot match given query to any API v2 endpoint. '
                         f'Invalid path {invalid_path}'), 404
