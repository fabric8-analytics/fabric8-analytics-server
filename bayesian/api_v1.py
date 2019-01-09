"""Definition of all REST API endpoints of the server module."""

import datetime
import functools
import uuid
import re
import urllib

import botocore
from requests_futures.sessions import FuturesSession
from flask import Blueprint, current_app, request, url_for, g
from flask.json import jsonify
from flask_restful import Api, Resource, reqparse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert
from selinon import StoragePool

from f8a_worker.models import (
    Ecosystem, StackAnalysisRequest, RecommendationFeedback)
from f8a_worker.utils import (MavenCoordinates, case_sensitivity_transform)
from f8a_worker.manifests import get_manifest_descriptor_by_filename

from . import rdb, cache
from .dependency_finder import DependencyFinder
from fabric8a_auth.auth import login_required
from .auth import get_access_token
from .exceptions import HTTPError
from .utils import (get_system_version, retrieve_worker_result,
                    server_create_component_bookkeeping,
                    server_create_analysis, get_analyses_from_graph,
                    search_packages_from_graph, get_request_count, fetch_file_from_github_release,
                    get_item_from_list_by_key_value, RecommendationReason,
                    retrieve_worker_results, get_next_component_from_graph, set_tags_to_component,
                    is_valid, get_recommendation_feedback_by_ecosystem, CveByDateEcosystemUtils,
                    server_run_flow, resolved_files_exist,
                    get_ecosystem_from_manifest)
from .license_extractor import extract_licenses

import os
from f8a_worker.storages import AmazonS3
from .default_config import COMPONENT_ANALYSES_LIMIT
from fabric8a_auth.errors import AuthError

# TODO: improve maintainability index
# TODO: https://github.com/fabric8-analytics/fabric8-analytics-server/issues/373

errors = {
        'AuthError': {
                         'status': 401,
                         'message': 'Authentication failed',
                         'some_description': 'Authentication failed'
                     }}

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
rest_api_v1 = Api(api_v1, errors=errors)

pagination_parser = reqparse.RequestParser()
pagination_parser.add_argument('page', type=int, default=0)
pagination_parser.add_argument('per_page', type=int, default=50)

ANALYSIS_ACCESS_COUNT_KEY = 'access_count'
TOTAL_COUNT_KEY = 'total_count'

ANALYTICS_API_VERSION = "v1.0"

worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)


@api_v1.route('/_error')
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


@api_v1.route('/readiness')
def readiness():
    """Handle the /readiness REST API call."""
    return jsonify({}), 200


@api_v1.route('/liveness')
def liveness():
    """Handle the /liveness REST API call."""
    # Check database connection
    current_app.logger.debug("Liveness probe - trying to connect to database "
                             "and execute a query")
    rdb.session.query(Ecosystem).count()
    return jsonify({}), 200


def get_item_skip(page, per_page):
    """Get the number of items to skip for the first page-1 pages."""
    return per_page * page


def get_item_relative_limit(page, per_page):
    """Get the maximum possible number of items on one page."""
    return per_page


def get_item_absolute_limit(page, per_page):
    """Get the total possible number of items."""
    return per_page * (page + 1)


def get_items_for_page(items, page, per_page):
    """Get all items for specified page and number of items to be used per page."""
    return items[get_item_skip(page, per_page):get_item_absolute_limit(page, per_page)]


# TODO: do we really need paginated output?

def paginated(func):
    """Provide paginated output for longer responses."""
    @functools.wraps(func)
    def inner(*args, **kwargs):
        func_res = func(*args, **kwargs)
        res, code, headers = func_res, 200, {}
        # TODO: please explain the logic for the code below:
        if isinstance(res, tuple):
            if len(res) == 3:
                res, code, headers = func_res
            elif len(res) == 2:
                res, code = func_res
            else:
                raise HTTPError('Internal error', 500)

        args = pagination_parser.parse_args()
        page, per_page = args['page'], args['per_page']
        count = res[TOTAL_COUNT_KEY]

        # first and last page handling
        previous_page = None if page == 0 else page - 1
        next_page = None if get_item_absolute_limit(page, per_page) >= count else page + 1

        view_args = request.view_args.copy()
        view_args['per_page'] = per_page

        view_args['page'] = previous_page
        paging = []
        if previous_page is not None:
            paging.append({'url': url_for(request.endpoint, **view_args), 'rel': 'prev'})
        view_args['page'] = next_page
        if next_page is not None:
            paging.append({'url': url_for(request.endpoint, **view_args), 'rel': 'next'})

        # put the info about pages into HTTP header for the response
        headers['Link'] = ', '.join(['<{url}>; rel="{rel}"'.format(**d) for d in paging])

        return res, code, headers

    return inner


# flask-restful doesn't actually store a list of endpoints, so we register them as they
#  pass through add_resource_no_matter_slashes
_resource_paths = []


def add_resource_no_matter_slashes(resource, route, endpoint=None, defaults=None):
    """Add a resource for both trailing slash and no trailing slash to prevent redirects."""
    slashless = route.rstrip('/')
    _resource_paths.append(api_v1.url_prefix + slashless)
    slashful = route + '/'
    endpoint = endpoint or resource.__name__.lower()
    defaults = defaults or {}

    # resources with and without slashes
    rest_api_v1.add_resource(resource,
                             slashless,
                             endpoint=endpoint + '__slashless',
                             defaults=defaults)
    rest_api_v1.add_resource(resource,
                             slashful,
                             endpoint=endpoint + '__slashful',
                             defaults=defaults)


class ApiEndpoints(Resource):
    """Implementation of / REST API call."""

    def get(self):
        """Handle the GET REST API call."""
        return {'paths': sorted(_resource_paths)}


class SystemVersion(Resource):
    """Implementation of /system/version REST API call."""

    @staticmethod
    def get():
        """Handle the GET REST API call."""
        return get_system_version()


class ComponentSearch(Resource):
    """Implementation of /component-search REST API call."""

    method_decorators = [login_required]

    def get(self, package):
        """Handle the GET REST API call."""
        if not package:
            msg = "Please enter a valid search term"
            raise HTTPError(202, msg)

        # Tokenize the search term before calling graph search
        result = search_packages_from_graph(re.split(r'\W+', package))
        return result


class ComponentAnalyses(Resource):
    """Implementation of all /component-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def get(ecosystem, package, version):
        """Handle the GET REST API call."""
        package = urllib.parse.unquote(package)
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        package = case_sensitivity_transform(ecosystem, package)
        result = get_analyses_from_graph(ecosystem, package, version)

        if result is not None:
            # Known component for Bayesian
            server_create_component_bookkeeping(ecosystem, package, version, g.decoded_token)
            return result

        if os.environ.get("INVOKE_API_WORKERS", "") == "1":
            # Enter the unknown path
            server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                   api_flow=True, force=False, force_graph_sync=True)
            msg = "Package {ecosystem}/{package}/{version} is unavailable. " \
                  "The package will be available shortly," \
                  " please retry after some time.".format(ecosystem=ecosystem, package=package,
                                                          version=version)
            raise HTTPError(202, msg)
        else:
            # no data has been found
            server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                   api_flow=False, force=False, force_graph_sync=True)
            msg = "No data found for {ecosystem} package " \
                  "{package}/{version}".format(ecosystem=ecosystem,
                                               package=package, version=version)
            raise HTTPError(404, msg)


class ComponentAnalysesPOST(Resource):
    """Implementation of /component-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()
        if not input_json:
            raise HTTPError(400, error="Expected JSON request")
        if type(input_json) != list:
            raise HTTPError(400, error="Expected list of dependencies in JSON request")
        if len(input_json) > COMPONENT_ANALYSES_LIMIT:
            raise HTTPError(400, error="Could not process more than {} dependencies at once."
                            .format(COMPONENT_ANALYSES_LIMIT))

        results = list()
        for dependency in input_json:
            ecosystem = dependency.get('ecosystem')
            package = dependency.get('package')
            version = dependency.get('version')
            if not all([ecosystem, package, version]):
                raise HTTPError(422, "provide the valid input.")
            if ecosystem == 'maven':
                package = MavenCoordinates.normalize_str(package)
            package = case_sensitivity_transform(ecosystem, package)
            result = get_analyses_from_graph(ecosystem, package, version)

            if result is not None:
                # Known component for Bayesian
                server_create_component_bookkeeping(ecosystem, package, version, g.decoded_token)
                results.append(result)

            elif os.environ.get("INVOKE_API_WORKERS", "") == "1":
                # Enter the unknown path
                server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                       api_flow=True, force=False, force_graph_sync=True)
                msg = "Package {ecosystem}/{package}/{version} is unavailable. " \
                    "The package will be available shortly," \
                    " please retry after some time.".format(ecosystem=ecosystem, package=package,
                                                            version=version)
                results.append({"package": package, "message": msg})
            else:
                # no data has been found
                server_create_analysis(ecosystem, package, version, user_profile=g.decoded_token,
                                       api_flow=False, force=False, force_graph_sync=True)
                msg = "No data found for {ecosystem} package " \
                    "{package}/{version}".format(ecosystem=ecosystem,
                                                 package=package, version=version)
                results.append({"package": package, "message": msg})
        return results, 200


class StackAnalysesGET(Resource):
    """Implementation of the /stack-analyses GET REST API call method."""

    method_decorators = [login_required]

    @staticmethod
    def get(external_request_id):
        """Handle the GET REST API call."""
        # TODO: reduce cyclomatic complexity
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        if get_request_count(rdb, external_request_id) < 1:
            raise HTTPError(404, "Invalid request ID '{t}'.".format(t=external_request_id))

        graph_agg = retrieve_worker_result(rdb, external_request_id, "GraphAggregatorTask")
        if graph_agg is not None and 'task_result' in graph_agg:
            if graph_agg['task_result'] is None:
                raise HTTPError(500, 'Invalid manifest file(s) received. '
                                     'Please submit valid manifest files for stack analysis')

        stack_result = retrieve_worker_result(rdb, external_request_id, "stack_aggregator_v2")
        reco_result = retrieve_worker_result(rdb, external_request_id, "recommendation_v2")

        if stack_result is None and reco_result is None:
            raise HTTPError(202, "Analysis for request ID '{t}' is in progress".format(
                t=external_request_id))

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
                                                                   stack.get(
                                                                       "manifest_file_path"))
            for dep in user_stack_deps:
                # Adding topics from the recommendations
                if stack_recommendation is not None:
                    dep["topic_list"] = stack_recommendation.get("input_stack_topics",
                                                                 {}).get(dep.get('name'), [])
                else:
                    dep["topic_list"] = []

        for stack in stacks:
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


@api_v1.route('/stack-analyses/<external_request_id>/_debug')
@login_required
def stack_analyses_debug(external_request_id):
    """Debug endpoint exposing operational data for particular stack analysis.

    This endpoint is not part of the public API.

    Note the existence of the data is not guaranteed,
    therefore the endpoint can return 404 even for valid request IDs.
    """
    results = retrieve_worker_results(rdb, external_request_id)
    if not results:
        return jsonify(error='No operational data for the request ID'), 404

    response = {'tasks': []}
    for result in results:
        op_data = result.to_dict()
        audit = op_data.get('task_result', {}).get('_audit', {})
        task_data = {'task_name': op_data.get('worker'),
                     'started_at': audit.get('started_at'),
                     'ended_at': audit.get('ended_at'),
                     'error': op_data.get('error')}
        response['tasks'].append(task_data)
    return jsonify(response), 200


class UserFeedback(Resource):
    """Implementation of /user-feedback POST REST API call."""

    method_decorators = [login_required]
    _ANALYTICS_BUCKET_NAME = "{}-{}".format(
        os.environ.get('DEPLOYMENT_PREFIX', 'unknown'),
        os.environ.get("AWS_ANALYTICS_BUCKET", "bayesian-user-feedback"))

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()
        # TODO: refactor the business logic into its own function defined outside api_v1.py

        # TODO: two cases should be handled here:
        # 1) no JSON at all
        # 2) JSON without 'request_id'
        if not request.json or 'request_id' not in input_json:
            raise HTTPError(400, error="Expected JSON request")

        if 'feedback' not in input_json:
            raise HTTPError(400, error="Expected feedback")

        s3 = AmazonS3(bucket_name=UserFeedback._ANALYTICS_BUCKET_NAME)
        s3.connect()
        # Store data
        key = "{}".format(input_json["request_id"])
        s3.store_dict(input_json, key)

        return {'status': 'success'}


class UserIntent(Resource):
    """Implementation of /user-intent POST REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        input_json = request.get_json()

        if not input_json:
            raise HTTPError(400, error="Expected JSON request")

        if 'manual_tagging' not in input_json:
            if 'ecosystem' not in input_json:
                raise HTTPError(400, error="Expected ecosystem in the request")

            if 'data' not in input_json:
                raise HTTPError(400, error="Expected data in the request")

            # TODO: please use proper class constant here, like in
            # UserFeedback._ANALYTICS_BUCKET_NAME
            s3 = StoragePool.get_connected_storage('S3UserIntent')

            # Store data
            return s3.store_master_tags(input_json)
        else:
            if 'user' not in input_json:
                raise HTTPError(400, error="Expected user name in the request")

            if 'data' not in input_json:
                raise HTTPError(400, error="Expected tags in the request")

            # TODO: please use proper class constant here, like in
            # UserFeedback._ANALYTICS_BUCKET_NAME
            s3 = StoragePool.get_connected_storage('S3ManualTagging')

            # Store data
            return s3.store_user_data(input_json)


class UserIntentGET(Resource):
    """Implementation of /user-intent GET REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def get(user, ecosystem):
        """Handle the GET REST API call."""
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        if not user:
            raise HTTPError(400, error="Expected user name in the request")

        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

        # TODO: please use proper class constant here, like in
        s3 = StoragePool.get_connected_storage('S3ManualTagging')
        # get user data
        try:
            result = s3.fetch_user_data(user, ecosystem)
        except botocore.exceptions.ClientError:
            err_msg = "Failed to fetch data for the user {u}, ecosystem {e}".format(u=user,
                                                                                    e=ecosystem)
            current_app.logger.exception(err_msg)
            raise HTTPError(404, error=err_msg)

        return result


class MasterTagsGET(Resource):
    """Implementation of /master-tags REST API call."""

    method_decorators = [login_required]

    # TODO: move the timeout constant to the config file

    @staticmethod
    @cache.memoize(timeout=604800)  # 7 days
    def get(ecosystem):
        """Handle the GET REST API call."""
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

        # TODO: please use proper class constant here, like in
        s3 = StoragePool.get_connected_storage('S3UserIntent')

        # get user data
        try:
            result = s3.fetch_master_tags(ecosystem)
        except botocore.exceptions.ClientError:
            err_msg = "Failed to fetch master tags for the ecosystem {e}".format(e=ecosystem)
            current_app.logger.exception(err_msg)
            raise HTTPError(404, error=err_msg)

        return result

    def __repr__(self):
        """Return textual representatin of classname + the id."""
        return "{}({})".format(self.__class__.__name__, self.id)


class GetNextComponent(Resource):
    """Implementation of all /get-next-component REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post(ecosystem):
        """Handle the POST REST API call."""
        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

        # TODO: refactor the business logic into its own function defined outside api_v1.py
        pkg = get_next_component_from_graph(
            ecosystem,
            g.decoded_token.get('email'),
            g.decoded_token.get('company'),
        )
        # check for package data
        if pkg:
            return pkg[0]
        else:
            raise HTTPError(200, error="No package found for tagging.")


class SetTagsToComponent(Resource):
    """Implementation of all /set-tags REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()

        # sanity checks
        if not input_json:
            raise HTTPError(400, error="Expected JSON request")

        # ecosystem name is expexted in the payload
        if 'ecosystem' not in input_json:
            raise HTTPError(400, error="Expected ecosystem in the request")

        # component name is expexted in the payload
        if 'component' not in input_json:
            raise HTTPError(400, error="Expected component in the request")

        # at least one tag is expexted in the payload
        if 'tags' not in input_json or not any(input_json.get('tags', [])):
            raise HTTPError(400, error="Expected some tags in the request")

        # start the business logic
        status, _error = set_tags_to_component(input_json.get('ecosystem'),
                                               input_json.get('component'),
                                               input_json.get('tags'),
                                               g.decoded_token.get('email'),
                                               g.decoded_token.get('company'))
        if status:
            return {'status': 'success'}, 200
        else:
            raise HTTPError(400, error=_error)


class StackAnalyses(Resource):
    """Implementation of all /stack-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        # TODO: reduce cyclomatic complexity
        # TODO: refactor the business logic into its own function defined outside api_v1.py
        github_token = get_access_token('github')
        sid = request.args.get('sid')
        license_files = list()
        check_license = request.args.get('check_license', 'false') == 'true'
        github_url = request.form.get("github_url")
        ref = request.form.get('github_ref')
        is_scan_enabled = request.headers.get('IsScanEnabled', "false")
        ecosystem = request.headers.get('ecosystem')
        origin = request.headers.get('origin')
        scan_repo_url = request.headers.get('ScanRepoUrl')

        # TODO: is not it better to use map of synonyms, for example?
        if ecosystem == "node":
            ecosystem = "npm"

        if ecosystem == "python":
            ecosystem = "pypi"

        if ecosystem == "golang":
            ecosystem = "golang"

        if ecosystem == "java":
            ecosystem = "maven"

        source = request.form.get('source')
        if not (scan_repo_url and ecosystem):
            if github_url is not None:
                files = fetch_file_from_github_release(url=github_url,
                                                       filename='pom.xml',
                                                       token=github_token.get('access_token'),
                                                       ref=ref)
            else:
                files = request.files.getlist('manifest[]')
                filepaths = request.values.getlist('filePath[]')
                license_files = request.files.getlist('license[]')

                current_app.logger.info('%r' % files)
                current_app.logger.info('%r' % filepaths)

                # At least one manifest file path should be present to analyse a stack
                if not filepaths:
                    raise HTTPError(400, error="Error processing request. "
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
        else:
            files = []
        dt = datetime.datetime.now()
        if sid:
            request_id = sid
            is_modified_flag = {'is_modified': True}
        else:
            request_id = uuid.uuid4().hex
            is_modified_flag = {'is_modified': False}

        manifests = []
        for index, manifest_file_raw in enumerate(files):
            if github_url is not None:
                filename = manifest_file_raw.get('filename', None)
                filepath = manifest_file_raw.get('filepath', None)
                content = manifest_file_raw.get('content')
            else:
                filename = manifest_file_raw.filename
                filepath = filepaths[index]
                content = manifest_file_raw.read().decode('utf-8')
            # For flow generating from build, we need not goto mercator
            if origin != "vscode" and not resolved_files_exist(filename):
                # check if manifest files with given name are supported
                manifest_descriptor = get_manifest_descriptor_by_filename(filename)
                if manifest_descriptor is None:
                    raise HTTPError(400, error="Manifest file '{filename}' is not supported".format(
                        filename=filename))

                # Check if the manifest is valid
                if not manifest_descriptor.validate(content):
                    raise HTTPError(400,
                                    error="Error processing request. Please upload a valid "
                                          "manifest file '{filename}'".format(filename=filename))

            # Record the response details for this manifest file

            manifest = {'filename': filename,
                        'content': content,
                        'ecosystem': ecosystem or manifest_descriptor.ecosystem,
                        'filepath': filepath}

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
                deps = d.scan_and_find_dependencies(ecosystem, manifests)
            elif scan_repo_url and ecosystem:
                # This condition is for the build flow
                args = {'git_url': scan_repo_url,
                        'ecosystem': ecosystem,
                        'is_scan_enabled': is_scan_enabled,
                        'request_id': request_id,
                        'is_modified_flag': is_modified_flag,
                        'auth_key': request.headers.get('Authorization'),
                        'check_license': check_license,
                        'gh_token': github_token
                        }
                server_run_flow('gitOperationsFlow', args)
                # Flag to prevent calling of backbone twice
                worker_flow_enabled = True
            else:
                # The default flow via mercator
                deps = d.execute(args, rdb.session, manifests, source)

            deps['external_request_id'] = request_id
            deps['current_stack_license'] = extract_licenses(license_files)
            deps.update(is_modified_flag)

            if not worker_flow_enabled:
                # No need to call backbone if its already called via worker flow
                _session.post(
                    '{}/api/v1/stack_aggregator'.format(api_url), json=deps,
                    params={'check_license': str(check_license).lower()})
                _session.post('{}/api/v1/recommender'.format(api_url), json=deps,
                              params={'check_license': str(check_license).lower()})

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
        """Handle the GET REST API call."""
        raise HTTPError(404, "Unsupported API endpoint")


class SubmitFeedback(Resource):
    """Implementation of /submit-feedback POST REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()
        if not request.json:
            raise HTTPError(400, error="Expected JSON request")

        stack_id = input_json.get('stack_id')
        recommendation_type = input_json.get('recommendation_type')
        package_name = input_json.get('package_name')
        feedback_type = input_json.get('feedback_type')
        ecosystem_name = input_json.get('ecosystem')
        conditions = [is_valid(stack_id),
                      is_valid(recommendation_type),
                      is_valid(package_name),
                      is_valid(feedback_type),
                      is_valid(ecosystem_name)]
        if not all(conditions):
            raise HTTPError(400, error="Expected parameters missing")
        # Insert in a single commit. Gains - a) performance, b) avoid insert inconsistencies
        # for a single request
        try:
            ecosystem_obj = Ecosystem.by_name(rdb.session, name=ecosystem_name)
            req = RecommendationFeedback(
                stack_id=stack_id,
                package_name=package_name,
                recommendation_type=recommendation_type,
                feedback_type=feedback_type,
                ecosystem_id=ecosystem_obj.id
            )
            rdb.session.add(req)
            rdb.session.commit()
            return {'status': 'success'}
        except SQLAlchemyError as e:
            # TODO: please log the actual error too here
            current_app.logger.exception(
                'Failed to create new analysis request')
            raise HTTPError(
                500, "Error inserting log for request {t}".format(t=stack_id)) from e


class RecommendationFB(Resource):
    """Implementation of /recommendation_feedback/<ecosystem> API call."""

    @staticmethod
    def get(ecosystem):
        """Implement GET method."""
        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

        result = get_recommendation_feedback_by_ecosystem(ecosystem)
        return jsonify(result)


class CveByDateEcosystem(Resource):
    """Implementation of api endpoint for CVEs bydate & further filter by ecosystem if provided."""

    method_decorators = [login_required]

    @staticmethod
    def get(modified_date, ecosystem=None):
        """Implement GET Method."""
        if not modified_date:
            raise HTTPError(400, error="Expected date in the request")
        try:
            datetime.datetime.strptime(modified_date, '%Y%m%d')
        except ValueError:
            msg = 'Invalid datetime specified. Please specify in YYYYMMDD format'
            raise HTTPError(400, msg)
        getcve = CveByDateEcosystemUtils(modified_date, ecosystem)
        result = getcve.get_cves_by_date() if not ecosystem else getcve.get_cves_by_date_ecosystem()
        return jsonify(result), 200


add_resource_no_matter_slashes(ApiEndpoints, '')
add_resource_no_matter_slashes(ComponentSearch, '/component-search/<package>',
                               endpoint='get_components')
add_resource_no_matter_slashes(ComponentAnalyses,
                               '/component-analyses/<ecosystem>/<package>/<version>',
                               endpoint='get_component_analysis')
add_resource_no_matter_slashes(ComponentAnalysesPOST,
                               '/component-analyses',
                               endpoint='post_component_analysis')
add_resource_no_matter_slashes(SystemVersion, '/system/version')
add_resource_no_matter_slashes(StackAnalyses, '/stack-analyses')
add_resource_no_matter_slashes(StackAnalysesGET, '/stack-analyses/<external_request_id>')
add_resource_no_matter_slashes(UserFeedback, '/user-feedback')
add_resource_no_matter_slashes(UserIntent, '/user-intent')
add_resource_no_matter_slashes(UserIntentGET, '/user-intent/<user>/<ecosystem>')
add_resource_no_matter_slashes(MasterTagsGET, '/master-tags/<ecosystem>')
add_resource_no_matter_slashes(
    GetNextComponent, '/get-next-component/<ecosystem>')
add_resource_no_matter_slashes(SetTagsToComponent, '/set-tags')
add_resource_no_matter_slashes(SubmitFeedback, '/submit-feedback')
add_resource_no_matter_slashes(RecommendationFB, '/recommendation_feedback/<ecosystem>')
add_resource_no_matter_slashes(CveByDateEcosystem, '/cves/bydate/<modified_date>/<ecosystem>')


@api_v1.errorhandler(HTTPError)
def handle_http_error(err):
    """Handle HTTPError exceptions."""
    return jsonify({'error': err.error}), err.status_code


@api_v1.errorhandler(AuthError)
def api_401_handler(err):
    """Handle AuthError exceptions."""
    return jsonify(error=err.error), err.status_code


# workaround https://github.com/mitsuhiko/flask/issues/1498
# NOTE: this *must* come in the end, unless it'll overwrite rules defined
# after this
@api_v1.route('/<path:invalid_path>')
def api_404_handler(*args, **kwargs):
    """Handle all other routes not defined above."""
    return jsonify(error='Cannot match given query to any API v1 endpoint'), 404
