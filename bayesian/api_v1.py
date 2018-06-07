"""Definition of all REST API endpoints of the server module."""

import datetime
import functools
import uuid
import re

from io import StringIO
from collections import defaultdict

import botocore
from requests_futures.sessions import FuturesSession
from flask import Blueprint, current_app, request, url_for, Response
from flask.json import jsonify
from flask_restful import Api, Resource, reqparse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert
from selinon import StoragePool

from f8a_worker.models import (
    Ecosystem, StackAnalysisRequest, RecommendationFeedback)
from f8a_worker.schemas import load_all_worker_schemas, SchemaRef
from f8a_worker.utils import (MavenCoordinates, case_sensitivity_transform)
from f8a_worker.manifests import get_manifest_descriptor_by_filename

from . import rdb, cache
from .default_config import CORE_DEPENDENCIES_REPO_URL
from .dependency_finder import DependencyFinder
from .auth import login_required, decode_token, get_access_token
from .exceptions import HTTPError
from .schemas import load_all_server_schemas
from .utils import (get_system_version, retrieve_worker_result, get_cve_data,
                    server_create_component_bookkeeping, build_nested_schema_dict,
                    server_create_analysis, get_analyses_from_graph,
                    search_packages_from_graph, get_request_count, fetch_file_from_github_release,
                    get_item_from_list_by_key_value, RecommendationReason,
                    retrieve_worker_results, get_next_component_from_graph, set_tags_to_component,
                    is_valid, select_latest_version, get_categories_data)
from .license_extractor import extract_licenses

import os
from f8a_worker.storages import AmazonS3
from .generate_manifest import PomXMLTemplate
import urllib

# TODO: improve maintainability index

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
rest_api_v1 = Api(api_v1)

pagination_parser = reqparse.RequestParser()
pagination_parser.add_argument('page', type=int, default=0)
pagination_parser.add_argument('per_page', type=int, default=50)

ANALYSIS_ACCESS_COUNT_KEY = 'access_count'
TOTAL_COUNT_KEY = 'total_count'

original_handle_error = rest_api_v1.handle_error

ANALYTICS_API_VERSION = "v1.0"

worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)


# see <dir>.exceptions.HTTPError docstring
def handle_http_error(e):
    """Handle HTTPError exceptions."""
    if isinstance(e, HTTPError):
        res = jsonify({'error': e.error})
        res.status_code = e.status_code
        return res
    else:
        return original_handle_error(e)


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


api_v1.coreapi_http_error_handler = handle_http_error
# work around https://github.com/flask-restful/flask-restful/issues/542
rest_api_v1.handle_error = handle_http_error


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


def paginated(func):
    """Provide paginated output for longer responses."""
    @functools.wraps(func)
    def inner(*args, **kwargs):
        func_res = func(*args, **kwargs)
        res, code, headers = func_res, 200, {}
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

    rest_api_v1.add_resource(resource,
                             slashless,
                             endpoint=endpoint + '__slashless',
                             defaults=defaults)
    rest_api_v1.add_resource(resource,
                             slashful,
                             endpoint=endpoint + '__slashful',
                             defaults=defaults)


class ResourceWithSchema(Resource):
    """This class makes sure we can add schemas to any response returned by any API endpoint.

    If a subclass of ResourceWithSchema is supposed to add a schema, it has to:
    - either implement `add_schema` method (see its docstring for information on signature
      of this method)
    - or add a `schema_ref` (instance of `f8a_worker.schemas.SchemaRef`) class attribute.
      If this attribute is added, it only adds schema to response with `200` status code
      on `GET` request.
    Note that if both `schema_ref` and `add_schema` are defined, only the method will be used.
    """

    def add_schema(self, response, status_code, method):
        """Add schema to response.

        The schema must be dict containing 3 string values:
        name, version and url (representing name and version of the schema and its
        full url).

        :param response: dict, the actual response object returned by the view
        :param status_code: int, numeric representation of returned status code
        :param method: str, uppercase textual representation of used HTTP method
        :return: dict, modified response object that includes the schema
        """
        if hasattr(self, 'schema_ref') and status_code == 200 and method == 'GET':
            response['schema'] = {
                'name': self.schema_ref.name,
                'version': self.schema_ref.version,
                'url': PublishedSchemas.get_api_schema_url(name=self.schema_ref.name,
                                                           version=self.schema_ref.version)
            }
        return response

    def dispatch_request(self, *args, **kwargs):
        """Perform the request dispatching based on the standard Flask dispatcher."""
        response = super().dispatch_request(*args, **kwargs)

        method = request.method
        status_code = 200
        response_body = response
        headers = None

        if isinstance(response, tuple):
            response_body = response[0]
            if len(response) > 1:
                status_code = response[1]
            if len(response) > 2:
                headers = response[2]

        return self.add_schema(response_body, status_code, method), status_code, headers


class ApiEndpoints(ResourceWithSchema):
    """Implementation of / REST API call."""

    def get(self):
        """Handle the GET REST API call."""
        return {'paths': sorted(_resource_paths)}


class SystemVersion(ResourceWithSchema):
    """Implementation of /system/version REST API call."""

    @staticmethod
    def get():
        """Handle the GET REST API call."""
        return get_system_version()


class ComponentSearch(ResourceWithSchema):
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


class ComponentAnalyses(ResourceWithSchema):
    """Implementation of all /component-analyses REST API calls."""

    method_decorators = [login_required]

    schema_ref = SchemaRef('analyses_graphdb', '1-2-0')

    @staticmethod
    def get(ecosystem, package, version):
        """Handle the GET REST API call."""
        decoded = decode_token()
        package = urllib.parse.unquote(package)
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        package = case_sensitivity_transform(ecosystem, package)
        result = get_analyses_from_graph(ecosystem, package, version)

        if result is not None:
            # Known component for Bayesian
            server_create_component_bookkeeping(ecosystem, package, version, decoded)
            return result

        if os.environ.get("INVOKE_API_WORKERS", "") == "1":
            # Enter the unknown path
            server_create_analysis(ecosystem, package, version, user_profile=decoded,
                                   api_flow=True, force=False, force_graph_sync=True)
            msg = "Package {ecosystem}/{package}/{version} is unavailable. " \
                  "The package will be available shortly," \
                  " please retry after some time.".format(ecosystem=ecosystem, package=package,
                                                          version=version)
            raise HTTPError(202, msg)
        else:
            server_create_analysis(ecosystem, package, version, user_profile=decoded,
                                   api_flow=False, force=False, force_graph_sync=True)
            msg = "No data found for {ecosystem} package " \
                  "{package}/{version}".format(ecosystem=ecosystem,
                                               package=package, version=version)
            raise HTTPError(404, msg)

    @staticmethod
    def post(ecosystem, package, version):
        """Handle the POST REST API call."""
        decoded = decode_token()
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        package = case_sensitivity_transform(ecosystem, package)

        server_create_analysis(ecosystem, package, version,
                               user_profile=decoded or {}, api_flow=True, force=True,
                               force_graph_sync=False)
        return {}, 202


class StackAnalysesGET(ResourceWithSchema):
    """Implementation of the /stack-analyses GET REST API call method."""

    method_decorators = [login_required]
    # schema_ref = SchemaRef('stack_analyses', '2-1-4')

    @staticmethod
    def get(external_request_id):
        """Handle the GET REST API call."""
        # TODO: reduce cyclomatic complexity
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


class UserFeedback(ResourceWithSchema):
    """Implementation of /user-feedback POST REST API call."""

    method_decorators = [login_required]
    _ANALYTICS_BUCKET_NAME = "{}-{}".format(
        os.environ.get('DEPLOYMENT_PREFIX', 'unknown'),
        os.environ.get("AWS_ANALYTICS_BUCKET", "bayesian-user-feedback"))

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()

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


class UserIntent(ResourceWithSchema):
    """Implementation of /user-intent POST REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()

        if not input_json:
            raise HTTPError(400, error="Expected JSON request")

        if 'manual_tagging' not in input_json:
            if 'ecosystem' not in input_json:
                raise HTTPError(400, error="Expected ecosystem in the request")

            if 'data' not in input_json:
                raise HTTPError(400, error="Expected data in the request")

            s3 = StoragePool.get_connected_storage('S3UserIntent')

            # Store data
            return s3.store_master_tags(input_json)
        else:
            if 'user' not in input_json:
                raise HTTPError(400, error="Expected user name in the request")

            if 'data' not in input_json:
                raise HTTPError(400, error="Expected tags in the request")

            s3 = StoragePool.get_connected_storage('S3ManualTagging')

            # Store data
            return s3.store_user_data(input_json)


class UserIntentGET(ResourceWithSchema):
    """Implementation of /user-intent GET REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def get(user, ecosystem):
        """Handle the GET REST API call."""
        if not user:
            raise HTTPError(400, error="Expected user name in the request")

        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

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


class MasterTagsGET(ResourceWithSchema):
    """Implementation of /master-tags REST API call."""

    method_decorators = [login_required]

    @staticmethod
    @cache.memoize(timeout=604800)  # 7 days
    def get(ecosystem):
        """Handle the GET REST API call."""
        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

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


class GetNextComponent(ResourceWithSchema):
    """Implementation of all /get-next-component REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post(ecosystem):
        """Handle the POST REST API call."""
        if not ecosystem:
            raise HTTPError(400, error="Expected ecosystem in the request")

        decoded = decode_token()

        pkg = get_next_component_from_graph(
            ecosystem,
            decoded.get('email'),
            decoded.get('company'),
        )
        if pkg:
            return pkg[0]
        else:
            raise HTTPError(200, error="No package found for tagging.")


class SetTagsToComponent(ResourceWithSchema):
    """Implementation of all /set-tags REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()
        decoded = decode_token()

        if not input_json:
            raise HTTPError(400, error="Expected JSON request")

        if 'ecosystem' not in input_json:
            raise HTTPError(400, error="Expected ecosystem in the request")

        if 'component' not in input_json:
            raise HTTPError(400, error="Expected component in the request")

        if 'tags' not in input_json or not any(input_json.get('tags', [])):
            raise HTTPError(400, error="Expected some tags in the request")

        status, _error = set_tags_to_component(input_json.get('ecosystem'),
                                               input_json.get('component'),
                                               input_json.get('tags'),
                                               decoded.get('email'),
                                               decoded.get('company'))
        if status:
            return {'status': 'success'}, 200
        else:
            raise HTTPError(400, error=_error)


class PublishedSchemas(ResourceWithSchema):
    """Implementation of all /schemas REST API calls."""

    API_COLLECTION = 'api'
    COMPONENT_ANALYSES_COLLECTION = 'component_analyses'
    schema_collections = {
        API_COLLECTION: build_nested_schema_dict(load_all_server_schemas()),
        COMPONENT_ANALYSES_COLLECTION: build_nested_schema_dict(load_all_worker_schemas())
    }

    def __init__(self):
        """Construct PublishedSchemas class instance and initialize id attribute for all schemas."""
        super(PublishedSchemas, self).__init__()
        for collection, schemas in self.schema_collections.items():
            for name, versions in schemas.items():
                for version, schema in versions.items():
                    url = self._get_schema_url(collection, name, version)
                    schema["id"] = url

    def get(self, collection=None, name=None, version=None):
        """Get the schema for specified collection, name, and version."""
        # Boring if statement instead of clever loop because Nick is no fun
        result = self.schema_collections
        if collection is not None:
            schema_path = [collection]
            result = self.schema_collections.get(collection)
            if result is not None and name is not None:
                schema_path.append(name)
                result = result.get(name)
                if result is not None and version is not None:
                    schema_path.append(version)
                    result = result.get(version)

        if result is None:
            raise HTTPError(404, 'Schema {} does not exist'.format('/'.join(schema_path)))
        return result

    @classmethod
    def _get_schema_url(cls, collection, name, version):
        return rest_api_v1.url_for(cls, collection=collection, name=name,
                                   version=version, _external=True)

    @classmethod
    def get_api_schema_url(cls, name, version):
        """Get the URL to given schema URL with the specified version."""
        return cls._get_schema_url(collection=cls.API_COLLECTION, name=name, version=version)

    @classmethod
    def get_component_analysis_schema_url(cls, name, version):
        """Get the URL to component analysis schema."""
        return cls._get_schema_url(collection=cls.COMPONENT_ANALYSES_COLLECTION,
                                   name=name, version=version)


class GenerateManifest(Resource):
    """Implementation of the /generate-file REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call with the manifest file."""
        input_json = request.get_json()
        if 'ecosystem' not in input_json:
            raise HTTPError(400, "Must provide an ecosystem")
        if input_json.get('ecosystem') == 'maven':
            return Response(
                PomXMLTemplate(input_json).xml_string(),
                headers={
                    "Content-disposition": 'attachment;filename=pom.xml',
                    "Content-Type": "text/xml;charset=utf-8"
                }
            )
        else:
            return Response(
                {'result': "ecosystem '{}' is not yet supported".format(
                    input_json['ecosystem'])},
                status=400
            )


class StackAnalyses(ResourceWithSchema):
    """Implementation of all /stack-analyses REST API calls."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        # TODO: reduce cyclomatic complexity
        decoded = decode_token()
        github_token = get_access_token('github')
        sid = request.args.get('sid')
        license_files = list()
        check_license = request.args.get('check_license', 'false') == 'true'
        github_url = request.form.get("github_url")
        ref = request.form.get('github_ref')
        user_email = request.headers.get('UserEmail')
        if not user_email:
            user_email = decoded.get('email', 'bayesian@redhat.com')

        source = request.form.get('source')
        if github_url is not None:
            files = fetch_file_from_github_release(url=github_url,
                                                   filename='pom.xml',
                                                   token=github_token.get('access_token'),
                                                   ref=ref)

        # TODO: Enable license when need to analyze current stack license
            # license = fetch_file_from_github(github_url, 'LICENSE')
            # if license:
            #     license_content = license[0].get('content')
            #     if license_content:
            #         license_files = [StringIO(license_content)]
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
                raise HTTPError(400, error="Error processing request. "
                                           "Number of manifests and filePaths must be the same.")

        # At least one manifest file should be present to analyse a stack
        if not files:
            raise HTTPError(400, error="Error processing request. "
                                       "Please upload a valid manifest files.")

        dt = datetime.datetime.now()
        if sid:
            request_id = sid
            is_modified_flag = {'is_modified': True}
        else:
            request_id = uuid.uuid4().hex
            is_modified_flag = {'is_modified': False}

        iso = datetime.datetime.utcnow().isoformat()

        manifests = []
        ecosystem = None
        for index, manifest_file_raw in enumerate(files):
            if github_url is not None:
                filename = manifest_file_raw.get('filename', None)
                filepath = manifest_file_raw.get('filepath', None)
                content = manifest_file_raw.get('content')
            else:
                filename = manifest_file_raw.filename
                filepath = filepaths[index]
                content = manifest_file_raw.read().decode('utf-8')

            # check if manifest files with given name are supported
            manifest_descriptor = get_manifest_descriptor_by_filename(filename)
            if manifest_descriptor is None:
                raise HTTPError(400, error="Manifest file '{filename}' is not supported".format(
                    filename=filename))

            # In memory file to be passed as an API parameter to /appstack
            manifest_file = StringIO(content)

            # Check if the manifest is valid
            if not manifest_descriptor.validate(content):
                raise HTTPError(400, error="Error processing request. Please upload a valid "
                                           "manifest file '{filename}'".format(filename=filename))

            # Record the response details for this manifest file
            manifest = {'filename': filename,
                        'content': content,
                        'ecosystem': manifest_descriptor.ecosystem,
                        'filepath': filepath}

            manifests.append(manifest)

        data = {'api_name': 'stack_analyses',
                'user_email': user_email,
                'user_profile': decoded}
        args = {'external_request_id': request_id,
                'ecosystem': ecosystem, 'data': data}

        try:
            api_url = current_app.config['F8_API_BACKBONE_HOST']

            d = DependencyFinder()
            deps = d.execute(args, rdb.session, manifests, source)
            deps['external_request_id'] = request_id
            deps['current_stack_license'] = extract_licenses(license_files)
            deps.update(is_modified_flag)

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
            raise HTTPError(500, "Error updating log for request {t}".format(t=sid)) from e

    @staticmethod
    def get():
        """Handle the GET REST API call."""
        raise HTTPError(404, "Unsupported API endpoint")


class SubmitFeedback(ResourceWithSchema):
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
            current_app.logger.exception(
                'Failed to create new analysis request')
            raise HTTPError(
                500, "Error inserting log for request {t}".format(t=stack_id)) from e


class DepEditorAnalyses(ResourceWithSchema):
    """Implementation of /depeditor-analyses POST REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        # TODO: reduce cyclomatic complexity
        manifest_file = {
            'maven': 'pom.xml',
            'node': 'package.json',
            'pypi': 'requirements.txt'
        }

        input_json = request.get_json()
        persist = request.args.get('persist', 'false') == 'true'
        if not input_json or 'request_id' not in input_json:
            raise HTTPError(400, error="Expected JSON request and request_id")

        if '_resolved' not in input_json or 'ecosystem' not in input_json:
            raise HTTPError(400, error="Expected _resolved and ecosystem in request")

        request_obj = {
            "external_request_id": input_json.get('request_id'),
            "result": [{
                "details": [{
                    "ecosystem": input_json.get('ecosystem'),
                    "_resolved": input_json.get('_resolved', []),
                    "manifest_file_path": input_json.get('manifest_file_path', '/path'),
                    "manifest_file": manifest_file.get(input_json.get('ecosystem'))
                }],
            }]
        }

        api_url = current_app.config['F8_API_BACKBONE_HOST']
        stack_agg_resp = _session.post('{}/api/v1/stack_aggregator'.format(api_url),
                                       json=request_obj, params={'persist': str(persist).lower()})
        recommender_resp = _session.post('{}/api/v1/recommender'.format(api_url),
                                         json=request_obj, params={'persist': str(persist).lower()})
        recommender_result = recommender_resp.result()
        stack_agg_result = stack_agg_resp.result()
        started_at = None
        finished_at = None
        version = None
        release = None
        manifest_response = []
        stacks = []
        recommendations = []
        stack_result = reco_result = dict()
        if stack_agg_result.status_code == 200:
            stack_result = stack_agg_result.json()
        if recommender_result.status_code == 200:
            reco_result = recommender_result.json()
        external_request_id = reco_result.get('external_request_id')
        if stack_result is not None and 'result' in stack_result:
            started_at = stack_result.get("result", {}).get(
                "_audit", {}).get("started_at", started_at)
            finished_at = stack_result.get("result", {}).get(
                "_audit", {}).get("ended_at", finished_at)
            version = stack_result.get("result", {}).get("_audit", {}).get("version", version)
            release = stack_result.get("result", {}).get("_release", release)
            stacks = stack_result.get("result", {}).get("stack_data", stacks)

        if reco_result is not None and 'result' in reco_result:
            recommendations = reco_result.get("result", {}).get("recommendations",
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
        if manifest_response[0].get('recommendation'):
            manifest_response = RecommendationReason().add_reco_reason(manifest_response)

        return {
            "version": version,
            "release": release,
            "started_at": started_at,
            "finished_at": finished_at,
            "request_id": external_request_id,
            "result": manifest_response,
            "dep_snapshot": input_json
        }


class DepEditorCVEAnalyses(ResourceWithSchema):
    """Implementation of /depeditor-cve-analyses POST REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def post():
        """Handle the POST REST API call."""
        input_json = request.get_json()

        if not request.json or 'request_id' not in input_json:
            raise HTTPError(400, error="Expected JSON request and request_id")

        if '_resolved' not in input_json or 'ecosystem' not in input_json:
            raise HTTPError(400, error="Expected _resolved and ecosystem in request")
        response = get_cve_data(input_json)
        return response, 200


class CategoryService(ResourceWithSchema):
    """Implementation of Dependency editor category service GET REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def get(runtime):
        """Handle the GET REST API call."""
        categories = defaultdict(lambda: {'pkg_count': 0, 'packages': list()})
        gremlin_resp = get_categories_data(runtime)
        response = {
            'categories': dict(),
            'request_id': gremlin_resp.get('requestId')
        }
        if 'result' in gremlin_resp and 'requestId' in gremlin_resp:
            data = gremlin_resp.get('result')
            if 'data' in data and data['data']:
                for items in data.get('data'):
                    category = items.get('category')
                    package = items.get('package')
                    if category and package:
                        pkg_count = category.get('category_deps_count', [0])[0]
                        _category = category.get('ctname', [''])[0]
                        pkg_name = package.get('name', [''])[0]
                        libio_version = package.get('libio_latest_version', [''])[0]
                        version = package.get('latest_version', [''])[0]
                        latest_version = select_latest_version(
                            version, libio_version, pkg_name)
                        categories[_category]['pkg_count'] = pkg_count
                        categories[_category]['packages'].append({
                            'name': pkg_name,
                            'version': latest_version,
                            'category': _category
                        })
                response['categories'] = categories
        return response, 200


class CoreDependencies(ResourceWithSchema):
    """Implementation of Blank booster /get-core-dependencies REST API call."""

    method_decorators = [login_required]

    @staticmethod
    def get(runtime):
        """Handle the GET REST API call."""
        try:
            url = CORE_DEPENDENCIES_REPO_URL
            resolved = list()
            fetched_file = fetch_file_from_github_release(url, 'core.json')
            dependencies = fetched_file[0].get('content', {})
            request_id = uuid.uuid4().hex
            for elem in dependencies[runtime]:
                packages = dict()
                packages["package"] = elem['groupId'] + ':' + elem['artifactId']
                packages["version"] = elem['version']
                if elem.get('scope'):
                    packages["scope"] = elem['scope']
                resolved.append(packages)
            response = {
                "_resolved": resolved,
                "ecosystem": "maven",
                "request_id": request_id
            }
            return response, 200
        except Exception as e:
            current_app.logger.error('ERROR: {}'.format(str(e)))


add_resource_no_matter_slashes(ApiEndpoints, '')
add_resource_no_matter_slashes(ComponentSearch, '/component-search/<package>',
                               endpoint='get_components')
add_resource_no_matter_slashes(ComponentAnalyses,
                               '/component-analyses/<ecosystem>/<package>/<version>',
                               endpoint='get_component_analysis')
add_resource_no_matter_slashes(SystemVersion, '/system/version')
add_resource_no_matter_slashes(StackAnalyses, '/stack-analyses')
add_resource_no_matter_slashes(StackAnalysesGET, '/stack-analyses/<external_request_id>')
add_resource_no_matter_slashes(UserFeedback, '/user-feedback')
add_resource_no_matter_slashes(UserIntent, '/user-intent')
add_resource_no_matter_slashes(UserIntentGET, '/user-intent/<user>/<ecosystem>')
add_resource_no_matter_slashes(MasterTagsGET, '/master-tags/<ecosystem>')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>',
                               endpoint='get_schemas_by_collection')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>/<name>',
                               endpoint='get_schemas_by_name')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>/<name>/<version>',
                               endpoint='get_schema_by_name_and_version')
add_resource_no_matter_slashes(GenerateManifest, '/generate-file')
add_resource_no_matter_slashes(
    GetNextComponent, '/get-next-component/<ecosystem>')
add_resource_no_matter_slashes(SetTagsToComponent, '/set-tags')
add_resource_no_matter_slashes(CategoryService, '/categories/<runtime>')
add_resource_no_matter_slashes(SubmitFeedback, '/submit-feedback')
add_resource_no_matter_slashes(DepEditorAnalyses, '/depeditor-analyses')
add_resource_no_matter_slashes(DepEditorCVEAnalyses, '/depeditor-cve-analyses')
add_resource_no_matter_slashes(CoreDependencies, '/get-core-dependencies/<runtime>')

# workaround https://github.com/mitsuhiko/flask/issues/1498
# NOTE: this *must* come in the end, unless it'll overwrite rules defined
# after this


@api_v1.route('/<path:invalid_path>')
def api_404_handler(*args, **kwargs):
    """Handle all other routes not defined above."""
    return jsonify(error='Cannot match given query to any API v1 endpoint'), 404
