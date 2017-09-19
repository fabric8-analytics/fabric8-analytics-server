import datetime
import functools
import uuid
import json
import requests
import re

from io import StringIO

from flask import Blueprint, current_app, request, url_for
from flask.json import jsonify
from flask_restful import Api, Resource, reqparse
from flask_cors import CORS
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from f8a_worker.models import Ecosystem, WorkerResult, StackAnalysisRequest
from f8a_worker.schemas import load_all_worker_schemas, SchemaRef
from f8a_worker.utils import (safe_get_latest_version, get_dependents_count,
                              get_component_percentile_rank, usage_rank2str,
                              MavenCoordinates, case_sensitivity_transform)
from f8a_worker.manifests import get_manifest_descriptor_by_filename
from . import rdb
from .auth import login_required, decode_token
from .exceptions import HTTPError
from .schemas import load_all_server_schemas
from .utils import (get_system_version, retrieve_worker_result,
                    server_create_component_bookkeeping, build_nested_schema_dict,
                    server_create_analysis, server_run_flow, get_analyses_from_graph,
                    search_packages_from_graph, get_request_count,
                    get_item_from_list_by_key_value, GithubRead)
import os
from f8a_worker.storages import AmazonS3

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
rest_api_v1 = Api(api_v1)
CORS(api_v1)

pagination_parser = reqparse.RequestParser()
pagination_parser.add_argument('page', type=int, default=0)
pagination_parser.add_argument('per_page', type=int, default=50)

ANALYSIS_ACCESS_COUNT_KEY = 'access_count'
TOTAL_COUNT_KEY = 'total_count'

original_handle_error = rest_api_v1.handle_error


# see <dir>.exceptions.HTTPError docstring
def handle_http_error(e):
    if isinstance(e, HTTPError):
        res = jsonify({'error': e.error})
        res.status_code = e.status_code
        return res
    else:
        return original_handle_error(e)


@api_v1.route('/_error')
def error():
    """This endpoint is used by httpd, which redirects its errors to it."""
    try:
        status = int(request.environ['REDIRECT_STATUS'])
    except:
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
    return jsonify({}), 200


@api_v1.route('/liveness')
def liveness():
    # Check database connection
    current_app.logger.warning("Liveness probe - trying to connect to database "
                               "and execute a query")
    rdb.session.query(Ecosystem).count()
    # Check broker connection
    current_app.logger.warning("Liveness probe - trying to schedule the livenessFlow")
    server_run_flow('livenessFlow', None)
    current_app.logger.warning("Liveness probe finished")
    return jsonify({}), 200


api_v1.coreapi_http_error_handler = handle_http_error
# work around https://github.com/flask-restful/flask-restful/issues/542
rest_api_v1.handle_error = handle_http_error


def get_item_skip(page, per_page):
    return per_page * page


def get_item_relative_limit(page, per_page):
    return per_page


def get_item_absolute_limit(page, per_page):
    return per_page * (page + 1)


def get_items_for_page(items, page, per_page):
    return items[get_item_skip(page, per_page):get_item_absolute_limit(page, per_page)]


def paginated(func):
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
    """Adds a resource for both trailing slash and no trailing slash to prevent redirects.
    """
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
        """Add schema to response. The schema must be dict containing 3 string values:
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
    def get(self):
        return {'paths': sorted(_resource_paths)}


class SystemVersion(ResourceWithSchema):
    @staticmethod
    def get():
        return get_system_version()


class ComponentSearch(ResourceWithSchema):
    method_decorators = [login_required]

    def get(self, package):
        if not package:
            msg = "Please enter a valid search term"
            raise HTTPError(202, msg)

        # Tokenize the search term before calling graph search
        result = search_packages_from_graph(re.split('\W+', package))
        return result


class ComponentAnalyses(ResourceWithSchema):
    method_decorators = [login_required]

    schema_ref = SchemaRef('analyses_graphdb', '1-2-0')

    @staticmethod
    def get(ecosystem, package, version):
        decoded = decode_token()
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
            msg = "No data found for {ecosystem} Package " \
                  "{package}/{version}".format(ecosystem=ecosystem,
                                               package=package, version=version)
            raise HTTPError(404, msg)


class StackAnalysesGETV1(ResourceWithSchema):
    method_decorators = [login_required]
    schema_ref = SchemaRef('stack_analyses', '2-1-4')

    @staticmethod
    def get(external_request_id):
        if get_request_count(rdb, external_request_id) < 1:
            raise HTTPError(404, "Invalid request ID '{t}'.".format(t=external_request_id))

        stack_result = retrieve_worker_result(rdb, external_request_id, "stack_aggregator")
        reco_result = retrieve_worker_result(rdb, external_request_id, "recommendation")

        if stack_result is None and reco_result is None:
            raise HTTPError(202, "Analysis for request ID '{t}' is in progress".format(
                t=external_request_id))

        if stack_result == -1 and reco_result == -1:
            raise HTTPError(404, "Worker result for request ID '{t}' doesn't exist yet".format(
                t=external_request_id))

        started_at = None
        finished_at = None
        manifest_response = []
        recommendations = {}

        if stack_result is not None and 'task_result' in stack_result:
            if stack_result["task_result"] is not None:
                started_at = stack_result["task_result"]["_audit"]["started_at"]
                finished_at = stack_result["task_result"]["_audit"]["ended_at"]
                manifest_response.append(stack_result["task_result"])

        if reco_result is not None and 'task_result' in reco_result:
            if reco_result["task_result"] is not None:
                recommendations = reco_result['task_result']

        return {
            "started_at": started_at,
            "finished_at": finished_at,
            "request_id": external_request_id,
            "result": manifest_response,
            "recommendation": recommendations
        }


class StackAnalysesGET(ResourceWithSchema):
    method_decorators = [login_required]
    # schema_ref = SchemaRef('stack_analyses', '2-1-4')

    @staticmethod
    def get(external_request_id):
        if get_request_count(rdb, external_request_id) < 1:
            raise HTTPError(404, "Invalid request ID '{t}'.".format(t=external_request_id))

        graph_agg = retrieve_worker_result(rdb, external_request_id, "GraphAggregatorTask")
        if graph_agg is not None and 'task_result' in graph_agg:
            if graph_agg['task_result'] is None:
                raise HTTPError(500, 'Invalid manifest file(s) received. '
                                     'Please submit valid manifest files for stack analysis')

        stack_result = retrieve_worker_result(rdb, external_request_id, "stack_aggregator_v2")
        reco_result = retrieve_worker_result(rdb, external_request_id, "recommendation_v2")
        user_stack_sentiment_result = retrieve_worker_result(rdb, external_request_id,
                                                             "user_stack_sentiment_scorer")
        reco_pkg_sentiment_result = retrieve_worker_result(rdb, external_request_id,
                                                           "reco_pkg_sentiment_scorer")

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

        # Populate sentiment score for packages in user's stack
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
            user_stack_deps = stack.get('user_stack_info', {}).get('dependencies', [])
            for dep in user_stack_deps:
                if user_stack_sentiment_result is not None:
                    user_stack_sentiment_item = \
                        get_item_from_list_by_key_value(user_stack_sentiment_result.get(
                            'task_result', {}).get('sentiment', []), 'manifest_file_path',
                            stack.get('manifest_file_path'))
                    dep['sentiment']['overall_score'] = \
                        user_stack_sentiment_item.get(dep['name'], {}).get('score', 0)
                    dep['sentiment']['magnitude'] = \
                        user_stack_sentiment_item.get(dep['name'], {}).get('magnitude', 0)
                else:
                    dep['sentiment'] = {
                        "latest_comment": "",
                        "overall_score": 0,
                        "magnitude": 0
                    }

                # Adding topics from the recommendations
                stack_recommendation = get_item_from_list_by_key_value(recommendations,
                                                                       "manifest_file_path",
                                                                       stack.get("manifest_file_path"))
                if stack_recommendation is not None:
                    dep["topic_list"] = stack_recommendation.get("input_stack_topics",
                                                                 {}).get(dep.get('name'), [])
                else:
                    dep["topic_list"] = []

        # Populate sentiment score for recommended packages
        if recommendations:
            for recommendation in recommendations:
                alternate = recommendation['alternate']
                for pkg in alternate:
                    if reco_pkg_sentiment_result is not None:
                        reco_pkg_sentiment_item = \
                            get_item_from_list_by_key_value(reco_pkg_sentiment_result.get(
                                                                'task_result', {}).get('sentiment', []),
                                                            'manifest_file_path',
                                                            recommendation.get('manifest_file_path'))
                        pkg['sentiment']['overall_score'] = \
                            reco_pkg_sentiment_item.get(pkg['name'], {}).get('score', 0)
                        pkg['sentiment']['magnitude'] = \
                            reco_pkg_sentiment_item.get(pkg['name'], {}).get('magnitude', 0)
                    else:
                        pkg['sentiment'] = {
                            "latest_comment": "",
                            "overall_score": 0,
                            "magnitude": 0
                        }

                companion = recommendation['companion']
                for pkg in companion:
                    if reco_pkg_sentiment_result is not None:
                        reco_pkg_sentiment_item = get_item_from_list_by_key_value(reco_pkg_sentiment_result.get('task_result', {}).get('sentiment', []), 'manifest_file_path', recommendation.get('manifest_file_path'))
                        pkg['sentiment']['overall_score'] = reco_pkg_sentiment_item.get(pkg['name'], {}).get('score', 0)
                        pkg['sentiment']['magnitude'] = reco_pkg_sentiment_item.get(pkg['name'], {}).get('magnitude', 0)
                    else:
                        pkg['sentiment'] = {
                            "latest_comment": "",
                            "overall_score": 0,
                            "magnitude": 0
                        }

        for stack in stacks:
            stack["recommendation"] = get_item_from_list_by_key_value(recommendations,
                                                                      "manifest_file_path",
                                                                      stack.get("manifest_file_path"))
            manifest_response.append(stack)

        return {
            "version": version,
            "release": release,
            "started_at": started_at,
            "finished_at": finished_at,
            "request_id": external_request_id,
            "result": manifest_response
        }


class UserFeedback(ResourceWithSchema):
    method_decorators = [login_required]
    _ANALYTICS_BUCKET_NAME = "{}-{}".format(os.environ.get('DEPLOYMENT_PREFIX', 'unknown'),
                                            os.environ.get("AWS_ANALYTICS_BUCKET", "bayesian-user-feedback"))

    @staticmethod
    def post():
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


class StackAnalysesV1(ResourceWithSchema):
    method_decorators = [login_required]

    @staticmethod
    def post():
        decoded = decode_token()
        github_url = request.form.get("github_url")
        if github_url is not None:
            files = GithubRead().get_files_github_url(github_url)
        else:
            files = request.files.getlist('manifest[]')
            filepaths = request.values.getlist('filePath[]')
        dt = datetime.datetime.now()
        origin = request.form.get('origin')

        # At least one manifest file should be present to analyse a stack
        if len(files) <= 0:
            raise HTTPError(400, error="Error processing request. "
                                       "Please upload a valid manifest files.")

        # At least one manifest file path should be present to analyse a stack
        if github_url is None:
            if len(filepaths) <= 0:
                raise HTTPError(400, error="Error processing request. "
                                           "Please send a valid manifest file path")

        request_id = uuid.uuid4().hex
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
                raise HTTPError(400, error="Manifest file '{filename}' is not supported".format(filename=filename))

            # In memory file to be passed as an API parameter to /appstack
            manifest_file = StringIO(content)

            # Check if the manifest is valid
            if not manifest_descriptor.validate(content):
                raise HTTPError(400, error="Error processing request. Please upload a valid manifest file '{filename}'"
                                .format(filename=filename))

            # appstack API call
            # Limitation: Currently, appstack can support only package.json
            #             The following condition is to be reworked
            appstack_id = ''
            if 'package.json' in filename:
                appstack_files = {'packagejson': manifest_file}
                url = current_app.config["BAYESIAN_ANALYTICS_URL"]
                endpoint = "{analytics_baseurl}/api/v1.0/appstack".format(analytics_baseurl=url)
                try:
                    response = requests.post(endpoint, files=appstack_files)
                except Exception as exc:
                    current_app.logger.warn("Analytics query: {}".format(exc))
                else:
                    if response.status_code == 200:
                        resp = response.json()
                        appstack_id = resp.get('appstack_id', '')
                    else:
                        current_app.logger.warn("{status}: {error}".format(status=response.status_code,
                                                                           error=response.content))

            # Record the response details for this manifest file
            manifest = {'filename': filename, 'content': content, 'ecosystem': manifest_descriptor.ecosystem, 'filepath': filepath}
            if appstack_id != '':
                manifest['appstack_id'] = appstack_id

            manifests.append(manifest)

        # Insert in a single commit. Gains - a) performance, b) avoid insert inconsistencies
        # for a single request
        try:
            req = StackAnalysisRequest(
                id=request_id,
                submitTime=str(dt),
                requestJson={'manifest': manifests},
                origin=origin
            )
            rdb.session.add(req)
            rdb.session.commit()
        except SQLAlchemyError as e:
            current_app.logger.exception('Failed to create new analysis request')
            raise HTTPError(500, "Error inserting log for request {t}".format(t=request_id)) from e

        try:
            args = {'external_request_id': request_id, 'manifest': manifests,
                    'ecosystem': ecosystem}
            server_run_flow('stackApiGraphFlow', args)
        except Exception as exc:
            # Just log the exception here for now
            current_app.logger.exception('Failed to schedule AggregatingMercatorTask for id {id}'
                                         .format(id=request_id))
            raise HTTPError(500, "Error processing request {t}. manifest files could not be processed"
                                 .format(t=request_id)) from exc

        return {"status": "success", "submitted_at": str(dt), "id": str(request_id)}

    @staticmethod
    def get():
        raise HTTPError(404, "Unsupported API endpoint")


class StackAnalyses(ResourceWithSchema):
    method_decorators = [login_required]

    @staticmethod
    def post():
        decoded = decode_token()
        github_url = request.form.get("github_url")
        if github_url is not None:
            files = GithubRead().get_files_github_url(github_url)
        else:
            files = request.files.getlist('manifest[]')
            filepaths = request.values.getlist('filePath[]')
        dt = datetime.datetime.now()
        origin = request.form.get('origin')

        # At least one manifest file should be present to analyse a stack
        if len(files) <= 0:
            raise HTTPError(400, error="Error processing request. Please upload a valid manifest files.")

        # At least one manifest file path should be present to analyse a stack
        if github_url is None:
            if len(filepaths) <= 0:
                raise HTTPError(400, error="Error processing request. Please send a valid manifest file path")

        request_id = uuid.uuid4().hex
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
                raise HTTPError(400, error="Manifest file '{filename}' is not supported".format(filename=filename))

            # In memory file to be passed as an API parameter to /appstack
            manifest_file = StringIO(content)

            # Check if the manifest is valid
            if not manifest_descriptor.validate(content):
                raise HTTPError(400, error="Error processing request. Please upload a valid manifest file '{filename}'"
                                .format(filename=filename))

            # appstack API call
            # Limitation: Currently, appstack can support only package.json
            #             The following condition is to be reworked
            appstack_id = ''
            if 'package.json' in filename:
                appstack_files = {'packagejson': manifest_file}
                url = current_app.config["BAYESIAN_ANALYTICS_URL"]
                endpoint = "{analytics_baseurl}/api/v1.0/appstack".format(analytics_baseurl=url)
                try:
                    response = requests.post(endpoint, files=appstack_files)
                except Exception as exc:
                    current_app.logger.warn("Analytics query: {}".format(exc))
                else:
                    if response.status_code == 200:
                        resp = response.json()
                        appstack_id = resp.get('appstack_id', '')
                    else:
                        current_app.logger.warn("{status}: {error}".format(status=response.status_code,
                                                                           error=response.content))

            # Record the response details for this manifest file
            manifest = {'filename': filename,
                        'content': content,
                        'ecosystem': manifest_descriptor.ecosystem,
                        'filepath': filepath}
            if appstack_id != '':
                manifest['appstack_id'] = appstack_id

            manifests.append(manifest)

        # Insert in a single commit. Gains - a) performance, b) avoid insert inconsistencies
        # for a single request
        try:
            req = StackAnalysisRequest(
                id=request_id,
                submitTime=str(dt),
                requestJson={'manifest': manifests},
                origin=origin
            )
            rdb.session.add(req)
            rdb.session.commit()
        except SQLAlchemyError as e:
            current_app.logger.exception('Failed to create new analysis request')
            raise HTTPError(500, "Error inserting log for request {t}".format(t=request_id)) from e

        try:
            data = {'api_name': 'stack_analyses',
                    'user_email': decoded.get('email', 'bayesian@redhat.com'),
                    'user_profile': decoded}
            args = {'external_request_id': request_id, 'ecosystem': ecosystem, 'data': data}
            server_run_flow('stackApiGraphV2Flow', args)
        except Exception as exc:
            # Just log the exception here for now
            current_app.logger.exception('Failed to schedule AggregatingMercatorTask for id {id}'
                                         .format(id=request_id))
            raise HTTPError(500, "Error processing request {t}. manifest files "
                                 "could not be processed"
                                 .format(t=request_id)) from exc

        return {"status": "success", "submitted_at": str(dt), "id": str(request_id)}

    @staticmethod
    def get():
        raise HTTPError(404, "Unsupported API endpoint")


class StackAnalysesByOrigin(ResourceWithSchema):
    method_decorators = [login_required]

    @staticmethod
    def get(origin):
        try:
            results = rdb.session.query(StackAnalysisRequest)\
                                 .filter(StackAnalysisRequest.origin == origin)\
                                 .order_by(StackAnalysisRequest.submitTime.desc())
            results_array = [result.to_dict() for result in results]
        except SQLAlchemyError as exc:
            raise HTTPError(500, "Error retrieving stack analyses") from exc
        return {"status": "success", "results": results_array}


class StackAnalysesById(ResourceWithSchema):
    schema_ref = SchemaRef('stack_analyses', '2-1-3')

    def get(self, external_request_id):
        manifest_appstackid_map = {}
        try:
            results = rdb.session.query(StackAnalysisRequest)\
                                 .filter(StackAnalysisRequest.id == external_request_id)
            if results.count() <= 0:
                raise HTTPError(404, "Invalid request ID '{id}' received".format(id=external_request_id))

            row = results.first().to_dict()
            submitted_at = row["submitTime"]
            request_json = json.loads(row["requestJson"])

            for manifest in request_json["manifest"]:
                if manifest.get('appstack_id', 0):
                    manifest_appstackid_map[manifest["filename"]] = manifest["appstack_id"]

        except SQLAlchemyError as exc:
            raise HTTPError(500, "Error fetching data for request ID '{id}'".format(id=external_request_id))\
                from exc

        try:
            results = rdb.session.query(WorkerResult)\
                                 .filter(WorkerResult.external_request_id == external_request_id,
                                         WorkerResult.worker == "dependency_aggregator")
            if results.count() <= 0:
                raise HTTPError(202, "Analysis for request ID '{t}' is in progress".format(t=external_request_id))
        except SQLAlchemyError as exc:
            raise HTTPError(500, "Worker result for request ID '{t}' doesn't exist yet".format(t=external_request_id))\
                from exc

        try:
            if results.count() > 0:
                result = results.first().to_dict()
                audit = result["task_result"]["_audit"]
                manifest_response = []

                # TODO: this will probably need some refactoring

                for manifest in result["task_result"]["result"]:
                    for component in manifest["components"]:
                        component["latest_version"] = safe_get_latest_version(component["ecosystem"],
                                                                              component["name"])
                        component["dependents_count"] = get_dependents_count(component["ecosystem"],
                                                                             component["name"],
                                                                             component["version"], rdb.session)
                        rank = get_component_percentile_rank(
                            component["ecosystem"],
                            component["name"],
                            component["version"],
                            rdb.session
                        )
                        component["relative_usage"] = usage_rank2str(rank)
                    manifest_appstack_id = manifest_appstackid_map.get(manifest["manifest_name"],
                                                                       '')
                    if manifest_appstack_id != '':
                        url = current_app.config['BAYESIAN_ANALYTICS_URL']
                        endpoint = "{analytics_baseurl}/api/v1.0/recommendation/{appstack_id}"\
                                   .format(analytics_baseurl=url,
                                           appstack_id=manifest_appstack_id)
                        resp = requests.get(endpoint)
                        if resp.status_code == 200:
                            recommendation = resp.json()

                            # Adding URI of the stacks to the recommendation
                            if recommendation.get("input_stack", {}).get("appstack_id", "") != "":
                                uri = "{analytics_baseurl}/api/v1.0/appstack/{appstack_id}"\
                                      .format(analytics_baseurl=url,
                                              appstack_id=recommendation["input_stack"]["appstack_id"])
                                recommendation["input_stack"]["uri"] = uri

                            if recommendation.get("recommendations", {}).get("similar_stacks", "") != "":
                                for r in recommendation["recommendations"]["similar_stacks"]:
                                    if r["stack_id"] != "":
                                        r["uri"] = "{analytics_baseurl}/api/v1.0/appstack/{appstack_id}"\
                                            .format(analytics_baseurl=url, appstack_id=r["stack_id"])
                            manifest["recommendation"] = recommendation
                        else:
                            current_app.logger.warn("{status}: {error}".format(status=resp.status_code,
                                                                               error=resp.content))

                    manifest_response.append(manifest)
                response = {
                    "status": result["task_result"]["status"],
                    "submitted_at": submitted_at,
                    "started_at": audit["started_at"],
                    "finished_at": audit["ended_at"],
                    "request_id": result["external_request_id"],
                    "result": manifest_response
                }
                return response
        except Exception as exc:
            raise HTTPError(500, "Error creating response for request {t}".format(
                t=external_request_id))\
                from exc


class PublishedSchemas(ResourceWithSchema):
    API_COLLECTION = 'api'
    COMPONENT_ANALYSES_COLLECTION = 'component_analyses'
    schema_collections = {
        API_COLLECTION: build_nested_schema_dict(load_all_server_schemas()),
        COMPONENT_ANALYSES_COLLECTION: build_nested_schema_dict(load_all_worker_schemas())
    }

    def __init__(self):
        super(PublishedSchemas, self).__init__()
        for collection, schemas in self.schema_collections.items():
            for name, versions in schemas.items():
                for version, schema in versions.items():
                    url = self._get_schema_url(collection, name, version)
                    schema["id"] = url

    def get(self, collection=None, name=None, version=None):
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
        return cls._get_schema_url(collection=cls.API_COLLECTION, name=name, version=version)

    @classmethod
    def get_component_analysis_schema_url(cls, name, version):
        return cls._get_schema_url(collection=cls.COMPONENT_ANALYSES_COLLECTION,
                                   name=name, version=version)


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
add_resource_no_matter_slashes(PublishedSchemas, '/schemas')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>',
                               endpoint='get_schemas_by_collection')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>/<name>',
                               endpoint='get_schemas_by_name')
add_resource_no_matter_slashes(PublishedSchemas, '/schemas/<collection>/<name>/<version>',
                               endpoint='get_schema_by_name_and_version')


# workaround https://github.com/mitsuhiko/flask/issues/1498
# NOTE: this *must* come in the end, unless it'll overwrite rules defined after this
@api_v1.route('/<path:invalid_path>')
def api_404_handler(*args, **kwargs):
    return jsonify(error='Cannot match given query to any API v1 endpoint'), 404
