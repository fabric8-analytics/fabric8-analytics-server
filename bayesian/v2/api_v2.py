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
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""Definition of all v2 REST API endpoints of the server module."""

import os
import urllib
import time
import datetime
import uuid
import json

from requests_futures.sessions import FuturesSession
from flask import Blueprint, current_app, request, g
from flask.json import jsonify
from flask_restful import Api, Resource

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from bayesian.v2.utility import VendorAnalyses
from bayesian import rdb
from bayesian.exceptions import HTTPError
from bayesian.utils import (get_system_version,
                            server_create_component_bookkeeping,
                            server_create_analysis,
                            check_for_accepted_ecosystem,
                            resolved_files_exist,
                            get_ecosystem_from_manifest,
                            server_run_flow,
                            fetch_sa_request,
                            retrieve_worker_result,
                            request_timed_out,
                            get_item_from_list_by_key_value,
                            RecommendationReason)
from bayesian.dependency_finder import DependencyFinder
from bayesian.license_extractor import extract_licenses

from fabric8a_auth.auth import login_required
from fabric8a_auth.errors import AuthError

from f8a_worker.utils import (MavenCoordinates, case_sensitivity_transform)
from f8a_worker.manifests import get_manifest_descriptor_by_filename
from f8a_worker.models import StackAnalysisRequest


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
import logging
_resource_paths = []
logger = logging.getLogger(__file__)


@api_v2.route('/readiness')
def readiness():
    """Handle the /readiness REST API call."""
    return jsonify({}), 200


@api_v2.route('/liveness')
def liveness():
    """Handle the /liveness REST API call."""
    # Check database connection
    current_app.logger.debug("Liveness probe - trying to connect to database "
                             "and execute a query")
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


class ComponentAnalyses(Resource):
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
        logger.info("Executed v2 API")
        package = urllib.parse.unquote(package)
        if not check_for_accepted_ecosystem(ecosystem):
            msg = "Ecosystem {ecosystem} is not supported for this request".format(
                ecosystem=ecosystem
            )
            raise HTTPError(400, msg)
        if ecosystem == 'maven':
            try:
                package = MavenCoordinates.normalize_str(package)
            except ValueError:
                msg = "Invalid maven format - {pkg}".format(
                    pkg=package
                )
                metrics_payload.update({"status_code": 400, "value": time.time() - st})
                _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)
                raise HTTPError(400, msg)
        package = case_sensitivity_transform(ecosystem, package)

        # Querying GraphDB for Vendor Specific CVE Info.
        graph_obj = VendorAnalyses(ecosystem, package, version)
        result = graph_obj.get_vendor_analyses()

        if result is not None:
            # Known component for Bayesian
            server_create_component_bookkeeping(ecosystem, package, version, g.decoded_token)

            metrics_payload.update({"status_code": 200, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)
            return result

        if os.environ.get("INVOKE_API_WORKERS", "") == "1":
            # Enter the unknown path
            server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                   api_flow=True, force=False, force_graph_sync=True)
            msg = "Package {ecosystem}/{package}/{version} is unavailable. " \
                  "The package will be available shortly," \
                  " please retry after some time.".format(ecosystem=ecosystem, package=package,
                                                          version=version)

            metrics_payload.update({"status_code": 202, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)

            return {'error': msg}, 202
        else:
            # no data has been found
            server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                   api_flow=False, force=False, force_graph_sync=True)
            msg = "No data found for {ecosystem} package " \
                  "{package}/{version}".format(ecosystem=ecosystem,
                                               package=package, version=version)

            metrics_payload.update({"status_code": 404, "value": time.time() - st})
            _session.post(url=METRICS_SERVICE_URL + "/api/v1/prometheus", json=metrics_payload)

            raise HTTPError(404, msg)


class StackAnalysesPost(Resource):
    """Implementation of all /stack-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        # TODO: reduce cyclomatic complexity
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        sid = request.args.get('sid')
        license_files = list()
        check_license = request.args.get('check_license', 'false') == 'true'
        is_scan_enabled = request.headers.get('IsScanEnabled', "false")
        ecosystem = request.headers.get('ecosystem')
        origin = request.headers.get('origin')
        show_transitive = request.headers.get('showTransitiveReport') \
            or os.environ.get('SHOW_TRANSITIVE_REPORT', "false")
        source = request.form.get('source')

        # Below ecosystem map tries to find the map entry.
        ecosystem_map = {
            "node": "npm",
            "python": "pypi",
            "java": "maven"
        }
        # If given ecosystem is not found in above map, than uses the value
        # passed in the request.
        ecosystem = ecosystem_map.get(ecosystem, ecosystem)
        current_app.logger.info("Final ecosystem: {ecosystem}".format(
                                    ecosystem=ecosystem))

        # ecosystem is not mandatory when origin is vscode, it will be read from manifest file,
        # otherwise API request should have ecosystem.
        if origin != "vscode" and not check_for_accepted_ecosystem(ecosystem):
            raise HTTPError(400,
                            error="Error processing request. "
                                  "'{ecosystem}' ecosystem is not supported".format(
                                      ecosystem=ecosystem))

        files = request.files.getlist('manifest[]')
        filepaths = request.values.getlist('filePath[]')
        license_files = request.files.getlist('license[]')

        current_app.logger.info('%r' % files)
        current_app.logger.info('%r' % filepaths)

        # At least one manifest file path should be present to analyse a stack
        if not filepaths:
            raise HTTPError(400,
                            error="Error processing request. "
                                  "Please send a valid manifest file path.")

        if len(files) != len(filepaths):
            raise HTTPError(400,
                            error="Error processing request. "
                                  "Number of manifests and filePaths must be the same.")

        # At least one manifest file should be present to analyse a stack
        if not files:
            raise HTTPError(400,
                            error="Error processing request. "
                                  "Please upload a valid manifest files.")

        dt = datetime.datetime.now()
        if sid:
            request_id = sid
            is_modified_flag = {'is_modified': True}
        else:
            request_id = uuid.uuid4().hex
            is_modified_flag = {'is_modified': False}

        manifests = []
        for index, manifest_file_raw in enumerate(files):
            filename = manifest_file_raw.filename
            filepath = filepaths[index]
            content = manifest_file_raw.read().decode('utf-8')

            # For flow generating from build, we need not goto mercator
            if origin != "vscode" and not resolved_files_exist(filename):
                # check if manifest files with given name are supported
                manifest_descriptor = get_manifest_descriptor_by_filename(filename)
                if manifest_descriptor is None:
                    raise HTTPError(400,
                                    error="Error processing request. "
                                          "Manifest file '{filename}' is not supported".format(
                                               filename=filename))

                # Check if the manifest is valid
                if not manifest_descriptor.validate(content):
                    raise HTTPError(400,
                                    error="Error processing request. Please upload a valid "
                                          "manifest file '{filename}'".format(
                                               filename=filename))

            # Record the response details for this manifest file

            manifest = {'filename': filename,
                        'content': content,
                        'filepath': filepath}
            try:
                # Exception is raised when origin is vscode and ecosystem header is not set.
                manifest['ecosystem'] = ecosystem or manifest_descriptor.ecosystem
            except UnboundLocalError:
                raise HTTPError(400, error="Error processing request, "
                                           "'ecosystem' header must be set.")

            manifests.append(manifest)

            if not ecosystem:
                ecosystem = get_ecosystem_from_manifest(manifests)

        data = {'api_name': 'stack_analyses'}
        args = {'external_request_id': request_id,
                'ecosystem': ecosystem, 'data': data}
        try:
            api_url = current_app.config['F8_API_BACKBONE_HOST']
            d = DependencyFinder()
            deps = {}
            worker_flow_enabled = False

            if resolved_files_exist(manifests):
                # This condition is for the flow from vscode
                deps = d.scan_and_find_dependencies(ecosystem, manifests, show_transitive)
            elif ecosystem:
                # This condition is for the build flow
                args = {'ecosystem': ecosystem,
                        'is_scan_enabled': is_scan_enabled,
                        'request_id': request_id,
                        'is_modified_flag': is_modified_flag,
                        'auth_key': request.headers.get('Authorization'),
                        'check_license': check_license
                        }
                server_run_flow('gitOperationsFlow', args)
                # Flag to prevent calling of backbone twice
                worker_flow_enabled = True
            else:
                # The default flow via mercator
                deps = d.execute(args, rdb.session, manifests, source)

            deps['external_request_id'] = request_id
            deps['current_stack_license'] = extract_licenses(license_files)
            deps['show_transitive'] = show_transitive
            deps.update(is_modified_flag)

            if not worker_flow_enabled:
                # No need to call backbone if its already called via worker flow
                _session.post(
                    '{}/api/v1/stack_aggregator'.format(api_url), json=deps,
                    params={'check_license': str(check_license).lower()})
                _session.post('{}/api/v1/recommender'.format(api_url), json=deps,
                              params={'check_license': str(check_license).lower()})
        except (ValueError, json.JSONDecodeError) as e:
            HTTPError(400, "Invalid dependencies encountered. %r" % e)
        except Exception as exc:
            raise HTTPError(500, ("Could not process {t}."
                                  .format(t=request_id))) from exc
        try:
            insert_stmt = insert(StackAnalysisRequest).values(
                id=request_id,
                submitTime=str(dt),
                requestJson={'manifest': manifests},
                dep_snapshot=deps
            )
            do_update_stmt = insert_stmt.on_conflict_do_update(
                index_elements=['id'],
                set_=dict(dep_snapshot=deps)
            )
            rdb.session.execute(do_update_stmt)
            rdb.session.commit()
            return {"status": "success", "submitted_at": str(dt), "id": str(request_id)}
        except SQLAlchemyError as e:
            # TODO: please log the actual error too here
            raise HTTPError(500, "Error updating log for request {t}".format(t=sid)) from e

    @staticmethod
    def get():
        """
        Handle the GET REST API without any parameters.
        Dummy method, never expected to be called in normal/happy flow.
        Refere to StackAnalysesGet.get() method for actual handling.
        """
        HTTPError(400, "Error processing request. 'request id' missing")

class StackAnalysesGet:
    @staticmethod
    def post():
        """
        Handle the POST REST API.
        Dummy method, never expected to be called in normal/happy flow.
        Refer to StackAnalysesPost.post() method for actual handling.
        """

    @staticmethod
    def get(external_request_id):
        """Handle the GET REST API call."""
        # TODO: reduce cyclomatic complexity
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        db_result = fetch_sa_request(rdb, external_request_id)
        if db_result is None:
            raise HTTPError(404, "Invalid request ID '{t}'.".format(t=external_request_id))

        graph_agg = retrieve_worker_result(rdb, external_request_id, "GraphAggregatorTask")
        if graph_agg is not None and 'task_result' in graph_agg:
            if graph_agg['task_result'] is None:
                raise HTTPError(500, 'Invalid manifest file(s) received. '
                                     'Please submit valid manifest files for stack analysis')

        stack_result = retrieve_worker_result(rdb, external_request_id, "stack_aggregator_v2")
        reco_result = retrieve_worker_result(rdb, external_request_id, "recommendation_v2")

        if stack_result is None or reco_result is None:
            # If the response is not ready and the timeout period is over, send error 408
            if request_timed_out(db_result):
                raise HTTPError(408, "Stack analysis request {t} has timed out. Please retry "
                                     "with a new analysis.".format(t=external_request_id))
            else:
                return {'error': "Analysis for request ID '{t}' is in progress".format(
                    t=external_request_id)}, 202

        if stack_result == -1 and reco_result == -1:
            raise HTTPError(404, "Worker result for request ID '{t}' doesn't exist yet".format(
                t=external_request_id))

        started_at = None
        finished_at = None
        version = None
        release = None
        manifest_response = []
        stacks = []
        recommendations = []

        if stack_result is not None and 'task_result' in stack_result:
            started_at = stack_result.get("task_result", {}).get("_audit", {}).get("started_at",
                                                                                   started_at)
            finished_at = stack_result.get("task_result", {}).get("_audit", {}).get("ended_at",
                                                                                    finished_at)
            version = stack_result.get("task_result", {}).get("_audit", {}).get("version",
                                                                                version)
            release = stack_result.get("task_result", {}).get("_release", release)
            stacks = stack_result.get("task_result", {}).get("stack_data", stacks)

        if reco_result is not None and 'task_result' in reco_result:
            recommendations = reco_result.get("task_result", {}).get("recommendations",
                                                                     recommendations)

        if not stacks:
            return {
                "version": version,
                "release": release,
                "started_at": started_at,
                "finished_at": finished_at,
                "request_id": external_request_id,
                "result": manifest_response
            }
        for stack in stacks:
            user_stack_deps = stack.get('user_stack_info', {}).get('analyzed_dependencies', [])
            stack_recommendation = get_item_from_list_by_key_value(recommendations,
                                                                   "manifest_file_path",
                                                                   stack.get("manifest_file_path"))
            for dep in user_stack_deps:
                # Adding topics from the recommendations
                if stack_recommendation is not None:
                    dep["topic_list"] = stack_recommendation.get("input_stack_topics",
                                                                 {}).get(dep.get('name'), [])
                else:
                    dep["topic_list"] = []

            # There should not be any recommendations if there are no analyzed dependencies
            user_stack_deps_count = stack.get('user_stack_info', {}). \
                get('analyzed_dependencies_count', [])
            if user_stack_deps_count == 0:
                stack["recommendation"] = {
                    "alternate": [],
                    "companion": [],
                    "usage_outliers": [],
                    "input_stack_topics": {},
                    "manifest_file_path": stack.get("manifest_file_path", ""),
                    "missing_packages_pgm": []}
            else:
                stack["recommendation"] = get_item_from_list_by_key_value(
                    recommendations,
                    "manifest_file_path",
                    stack.get("manifest_file_path"))
            manifest_response.append(stack)

        # Populate reason for alternate and companion recommendation
        manifest_response = RecommendationReason().add_reco_reason(manifest_response)

        resp = {
            "version": version,
            "release": release,
            "started_at": started_at,
            "finished_at": finished_at,
            "request_id": external_request_id,
            "result": manifest_response
        }

        return resp


@api_v2.route('/_error')
def error():
    """Implement the endpoint used by httpd, which redirects its errors to it."""
    try:
        status = int(request.environ['REDIRECT_STATUS'])
    except Exception:
        # if there's an exception, it means that a client accessed this directly;
        #  in this case, we want to make it look like the endpoint is not here
        return api_404_handler()
    msg = 'Unknown error'
    # for now, we just provide specific error for stuff that already happened;
    #  before adding more, I'd like to see them actually happening with reproducers
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
add_resource_no_matter_slashes(ComponentAnalyses,
                               '/component-analyses/<ecosystem>/<package>/<version>',
                               endpoint='get_component_analyses')

# Stack analyses routes
add_resource_no_matter_slashes(StackAnalysesPost,
                               '/stack-analyses',
                               endpoint='post_stack_analyses')
add_resource_no_matter_slashes(StackAnalysesGet,
                               '/stack-analyses/<external_request_id>',
                               endpoint='get_stack_analyses')


# ERROR HANDLING

@api_v2.errorhandler(HTTPError)
def handle_http_error(err):
    """Handle HTTPError exceptions."""
    return jsonify({'error': err.error}), err.status_code


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
