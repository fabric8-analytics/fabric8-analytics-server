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
import html
import os
import time
import logging
from typing import Dict
import json
import hashlib
from pydantic.error_wrappers import ValidationError

from flask import Blueprint, request, redirect
from flask.json import jsonify

from fabric8a_auth.auth import login_required, AuthError
from bayesian.auth import validate_user
from bayesian.exceptions import HTTPError
from bayesian.utility.v2.component_analyses import ca_validate_input, \
    get_known_unknown_pkgs, add_unknown_pkg_info, get_batch_ca_data
from bayesian.utils import create_component_bookkeeping
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
from bayesian.default_config import (THREESCALE_USER_KEY, THREESCALE_API_URL,
                                     STACK_REPORT_UI_HOSTNAME)
from prometheus_flask_exporter.multiprocess import GunicornPrometheusMetrics
from prometheus_flask_exporter import NO_PREFIX

logger = logging.getLogger(__name__)

api_v2 = Blueprint('api_v2', __name__, url_prefix='/api/v2')

# metrics obj to be used to track endpoints
metrics = GunicornPrometheusMetrics(api_v2, group_by="endpoint", defaults_prefix=NO_PREFIX)



@api_v2.route('/component-vulnerability-analyses/', methods=['POST'])
@api_v2.route('/component-analyses', methods=['POST'])
@validate_user
@login_required
def component_analyses_post():
    """Handle the POST REST API call.

    Component Analyses Batch is 4 Step Process:
    1. Gather and clean Request.
    2. Query GraphDB.
    3. Build Stack Recommendation and Build Unknown Packages and Trigger componentApiFlow.
    4. Handle Unknown Packages and Trigger bayesianApiFlow.
    """
    input_json: Dict = request.get_json()
    ecosystem: str = input_json.get('ecosystem')
    if request.user_agent.string == "claircore/crda/RemoteMatcher":
        try:
            md5_hash = hashlib.md5(json.dumps(input_json, sort_keys=True).
                                   encode('utf-8')).hexdigest()
            logger.info("Ecosystem: %s => body md5 hash: %s", ecosystem, md5_hash)
        except Exception as e:
            logger.error("Exception %s", e)
        return jsonify({"message": "disabled"}), 404
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

    create_component_bookkeeping(ecosystem, packages_list, request.args, request.headers)

    # Step4: Handle Unknown Packages
    if unknown_pkgs:
        stack_recommendation = add_unknown_pkg_info(stack_recommendation, unknown_pkgs)
        pkgs_to_ingest = set(map(lambda pkg: ingestion_utils.Package(package=pkg.package,
                                                                     version=pkg.version),
                                 unknown_pkgs))
        logger.debug("Unknown ingestion triggered for %s", pkgs_to_ingest)
        unknown_package_flow(ecosystem, pkgs_to_ingest)
        return jsonify(stack_recommendation), 202

    return jsonify(stack_recommendation), 200


@api_v2.route('/component-analyses/<ecosystem>/<package>/<version>', methods=['GET'])
@validate_user
@login_required
def component_analyses_get(ecosystem, package, version):
    """Handle the GET REST API call.

    Component Analyses:
        - If package is Known (exists in GraphDB (Snyk Edge) returns Json formatted response.
        - If package is not Known: Call Util's function to trigger ingestion flow.

    :return:
        JSON Response
    """
    input_json = {
        "package_versions": [{
            "package": package,
            "version": version,
         }]
    }
    try:
        ca_validate_input(input_json, ecosystem)
        # Perform Component Analyses on Vendor specific Graph Edge.
        analyses_result = ComponentAnalyses(
            ecosystem, package, version).get_component_analyses_response()
    except BadRequest as br:
        logger.error(br)
        raise HTTPError(400, str(br)) from br

    if analyses_result is not None:
        return jsonify(analyses_result)

    # No data has been found
    unknown_pkgs = set()
    unknown_pkgs.add(ingestion_utils.Package(package=package, version=version))
    unknown_package_flow(ecosystem, unknown_pkgs)

    msg = {"message": f"No data found for {ecosystem} package {package}/{version}"}
    return jsonify(msg), 404


@api_v2.route('/component-analyses/', methods=['POST'])
@api_v2.route('/component-analyses', methods=['POST'])
@validate_user
@login_required
def component_analyses_post():
    """Handle the POST REST API call.

    Component Analyses Batch is 4 Step Process:
    1. Gather and clean Request.
    2. Query GraphDB.
    3. Build Stack Recommendation and Build Unknown Packages and Trigger componentApiFlow.
    4. Handle Unknown Packages and Trigger bayesianApiFlow.
    """
    input_json: Dict = request.get_json()
    ecosystem: str = input_json.get('ecosystem')
    if request.user_agent.string == "claircore/crda/RemoteMatcher":
        try:
            md5_hash = hashlib.md5(json.dumps(input_json, sort_keys=True).
                                   encode('utf-8')).hexdigest()
            logger.info("Ecosystem: %s => body md5 hash: %s", ecosystem, md5_hash)
        except Exception as e:
            logger.error("Exception %s", e)
        return jsonify({"message": "disabled"}), 404
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

    create_component_bookkeeping(ecosystem, packages_list, request.args, request.headers)

    # Step4: Handle Unknown Packages
    if unknown_pkgs:
        stack_recommendation = add_unknown_pkg_info(stack_recommendation, unknown_pkgs)
        pkgs_to_ingest = set(map(lambda pkg: ingestion_utils.Package(package=pkg.package,
                                                                     version=pkg.version),
                                 unknown_pkgs))
        logger.debug("Unknown ingestion triggered for %s", pkgs_to_ingest)
        unknown_package_flow(ecosystem, pkgs_to_ingest)
        return jsonify(stack_recommendation), 202

    return jsonify(stack_recommendation), 200


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


@api_v2.route('/stack-report/<stack_id>', methods=['GET'])
def stack_report_url(stack_id: str):
    """URL redirect for Stack Report UI."""
    stack_id: str = html.escape(stack_id)
    try:
        stack_request = RdbAnalyses(stack_id).get_request_data()
        crda_key = stack_request.user_id
    except (RDBServerException, RDBInvalidRequestException):
        logger.exception("Invalid Stack ID %s", stack_id)
        return jsonify({"error": f"Invalid Stack ID {stack_id}"}), 400
    if not crda_key:
        return jsonify({"error": "User corresponding to given Stack Id doesn't exists. "
                       "Please authenticate yourself and try again."}), 400
    path = f"{STACK_REPORT_UI_HOSTNAME}/#/analyze/{stack_id}"
    query_params = "?interframe=true&api_data=" + json.dumps({
        "access_token": "undefined",
        "route_config": {
            "api_url": THREESCALE_API_URL,
            "ver": "v3",
            "uuid": str(crda_key)
        },
        "user_key": THREESCALE_USER_KEY
    })
    final_path = path + query_params
    logger.info("Redirected to URL: %s ", final_path)
    return redirect(final_path, code=302)


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
