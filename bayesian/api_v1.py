import datetime
import functools
import urllib.parse
import uuid
import json
import requests

from requests_futures.sessions import FuturesSession

from io import StringIO

from flask import Blueprint, current_app, request, url_for, Response
from flask.json import jsonify
from flask_restful import Api, Resource, reqparse
from flask_security import current_user, login_required
from flask_cors import CORS
from sqlalchemy import func as sqlfunc
from sqlalchemy import or_
from sqlalchemy.orm import lazyload as sqllazyload
from sqlalchemy.sql import label as sqllabel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.exceptions import BadRequest

from cucoslib.solver import CucosReleasesFetcher, get_ecosystem_solver
from cucoslib.models import Analysis, Ecosystem, Package, Version, WorkerResult, StackAnalysisRequest
from cucoslib.schemas import load_all_worker_schemas, SchemaRef
from cucoslib.utils import (safe_get_latest_version, get_dependents_count, get_component_percentile_rank,
                            usage_rank2str, MavenCoordinates)
from cucoslib.manifests import get_manifest_descriptor_by_filename
from . import rdb
from .exceptions import HTTPError
from .schemas import load_all_server_schemas
from .utils import (get_latest_analysis_for, get_latest_analysis_by_hash, get_system_version,
                    do_projection, build_nested_schema_dict, server_create_analysis, server_run_flow,
                    get_analyses_from_graph)
from cucoslib.graphutils import (get_stack_usage_data_graph, get_stack_popularity_data_graph,
                         aggregate_stack_data)
import os
from cucoslib.storages import AmazonS3

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
    #  before adding more, I'd like to see them actually happenning with reproducers
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
    current_app.logger.warning("Liveness probe - trying to connect to database and execute a query")
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
    - or add a `schema_ref` (instance of `cucoslib.schemas.SchemaRef`) class attribute.
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
    def get(self):
        return get_system_version()


class Ecosystems(ResourceWithSchema):
    @paginated
    def get(self):
        args = pagination_parser.parse_args()
        count = rdb.session.query(Ecosystem).count()
        ecosystems = rdb.session.query(Ecosystem, sqllabel('pc', sqlfunc.count(Package.id))).\
            outerjoin(Package).\
            order_by(Ecosystem.name.asc()).\
            group_by(Ecosystem.id).\
            offset(get_item_skip(args['page'], args['per_page'])).\
            limit(get_item_relative_limit(args['page'], args['per_page']))
        return {TOTAL_COUNT_KEY: count,
                'items': [{'ecosystem': res.Ecosystem.name, 'url': res.Ecosystem.url,
                           'backend': res.Ecosystem.backend.name, 'package_count': res.pc}
                          for res in ecosystems]}


class Packages(ResourceWithSchema):
    @paginated
    def get(self, ecosystem):
        # TODO: only show packages with at least one successful analysis pass?
        args = pagination_parser.parse_args()
        if rdb.session.query(Ecosystem).filter(Ecosystem.name == ecosystem).count() == 0:
            raise HTTPError(404, "Ecosystem '{}' does not exist.".format(ecosystem))
        count = rdb.session.query(Package).join(Ecosystem).\
            filter(Ecosystem.name == ecosystem).\
            count()
        # the implicit join-load doesn't work well with group_by, so turn it of in options()
        packages = rdb.session.query(Package, sqllabel('vc', sqlfunc.count(Version.id))).\
            options(sqllazyload('ecosystem')).\
            join(Ecosystem).\
            filter(Ecosystem.name == ecosystem).\
            outerjoin(Version).\
            group_by(Ecosystem.id, Package.id).\
            order_by(Package.name.asc()).\
            offset(get_item_skip(args['page'], args['per_page'])).\
            limit(get_item_relative_limit(args['page'], args['per_page']))
        return {TOTAL_COUNT_KEY: count,
                'items': [{'ecosystem': res.Package.ecosystem.name, 'package': res.Package.name,
                           'version_count': res.vc} for res in packages]}


class Versions(ResourceWithSchema):
    @paginated
    def get(self, ecosystem, package):
        args = pagination_parser.parse_args()
        package = urllib.parse.unquote(package)
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        package_found = rdb.session.query(Package).\
            join(Ecosystem).\
            filter(Ecosystem.name == ecosystem, Package.name == package).\
            count()
        if package_found == 0:
            raise HTTPError(404, error="Package '{e}/{p}' not tracked".
                            format(p=package, e=ecosystem))
        query = rdb.session.query(Version).\
            join(Package).join(Ecosystem).\
            filter(Ecosystem.name == ecosystem, Package.name == package)
        count = query.count()
        versions = query.\
            filter(Ecosystem.name == ecosystem, Package.name == package).\
            order_by(Version.identifier.asc()).\
            offset(get_item_skip(args['page'], args['per_page'])).\
            limit(get_item_relative_limit(args['page'], args['per_page']))
        items = [{'ecosystem': ecosystem,
                  'package': package,
                  'version': v.identifier}
                 for v in versions]
        return {TOTAL_COUNT_KEY: count, 'items': items}


class AnalysisBase(ResourceWithSchema):
    """Base class for different endpoints returning analyses."""
    schema_ref = SchemaRef('component_analyses', '1-1-3')

    def add_schema(self, response, status_code, method):
        """Overrides add_schema to be able to add component analyses schemas."""
        super().add_schema(response, status_code, method)
        if status_code == 200 and method == 'GET':
            for analysis_name, analysis in response.get('analyses', {}).items():
                if analysis is not None and 'schema' in analysis:
                    analysis['schema']['url'] = PublishedSchemas.get_component_analysis_schema_url(
                        name=analysis['schema']['name'],
                        version=analysis['schema']['version']
                    )
        return response

    def _parse_args(self):
        args = ['fields', 'debuginfo']
        arg_parser = reqparse.RequestParser()
        for arg in args:
            arg_parser.add_argument(arg, default='')
        parsed_args = arg_parser.parse_args()
        result = {k: parsed_args[k] for k in args}
        result['debuginfo'] = result['debuginfo'].lower() == 'true'
        return result

    def _get_projection(self, fields):
        projection = {}
        if fields:
            for f in fields.split(','):
                projection[f] = 1
        return projection or None

    def _do_analysis_projection(self, analysis, fields):
        pass

    def _inc_access_counter(self, analysis):
        analysis.access_count += 1
        rdb.session.commit()

    def _sanitize_result(self, result, debuginfo=False):

        result['_release'] = result.pop('release', None)
        if debuginfo:
            result['_audit'] = result.pop('audit', None)
        else:
            result.pop('id', None)
            result.pop('audit', None)
            result.pop('subtasks', None)
            # Do not show init task
            result.get('analyses', {}).pop('InitAnalysisFlow', None)
            for analysis in result.get('analyses', {}):
                if result['analyses'][analysis]:
                    result['analyses'][analysis].pop('_audit', None)

        return result


class AnalysesEPVByGraph(ResourceWithSchema):
    schema_ref = SchemaRef('analyses_graphdb', '1-2-0')

    def get(self, ecosystem, package, version):
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        result = get_analyses_from_graph(ecosystem, package, version)
        current_app.logger.warn( "%r" % result)

        if result != None:
            # Known component for Bayesian
            return result

        # Enter the unknown path
        result = get_latest_analysis_for(ecosystem, package, version)
        if result == None:
            args = {'ecosystem': ecosystem, 'name': package, 'version': version}
            server_run_flow('graphSyncFlow', args)
            msg = "Package {ecosystem}:{package}:{version} is unavailable. The package will be available shortly,"\
                    " please rety after some time.".format(ecosystem=ecosystem, package=package, version=version)
            raise HTTPError(202, msg)

        # analyses is in-progress: data not available on graphdb yet
        return {'status': 'in-progress'}


class Analyses(AnalysisBase):
    def add_schema(self, response, status_code, method):
        # no schemas for analyses list
        return response

    def _get_sort_params(self):
        arg_parser = reqparse.RequestParser()
        arg_parser.add_argument('sort', default='')
        args = arg_parser.parse_args()
        sort = args['sort'].split(',')

        if not any(sort):
            sort = ['ecosystem', 'package', 'version', 'started_at']

        for param in sort:
            if param.startswith('-'):
                param = param[1:]
                if param in sort:
                    raise HTTPError(400, 'Both "-{p}", "{p}" in sort parameters'.format(p=param))
            if param not in [c.name for c in Analysis.__table__.columns] + ['ecosystem', 'package',
                                                                            'version']:
                raise HTTPError(400, 'Analysis doesn\'t have property "{p}"'.format(p=param))

        return sort

    def _get_order_attr(self, sort_opt):
        if sort_opt == 'ecosystem':
            return getattr(Ecosystem, 'name')
        elif sort_opt == 'package':
            return getattr(Package, 'name')
        elif sort_opt == 'version':
            return getattr(Version, 'identifier')
        else:
            return getattr(Analysis, sort_opt)

    @paginated
    def get(self):
        pargs = pagination_parser.parse_args()
        sort = self._get_sort_params()
        count = rdb.session.query(Analysis).count()

        # TODO: maybe it would make sense to create a SQL view for this?
        analyses = rdb.session.query(Analysis, Version.identifier, Package.name, Ecosystem.name).\
            join(Version).join(Package).join(Ecosystem)
        for s in sort:
            if s.startswith('-'):
                order_by = self._get_order_attr(s[1:]).desc()
            else:
                order_by = self._get_order_attr(s).asc()
            analyses = analyses.order_by(order_by)
        analyses = analyses. \
            offset(get_item_skip(pargs['page'], pargs['per_page'])). \
            limit(get_item_relative_limit(pargs['page'], pargs['per_page']))

        # make sure that analyses don't get loaded lazily by sanitizing results etc
        analyses_results = [res.Analysis.to_dict(omit_analyses=True) for res in analyses]
        return {'total_count': count,
                'items': [self._sanitize_result(a) for a in analyses_results],
                'truncated': True}

    def post(self):
        try:
            data = request.get_json()
            ecosystem = data['ecosystem']
            package = data['package']
            version = data['version']
        except (BadRequest, TypeError, KeyError):
            raise HTTPError(400, error="Invalid Request")

        server_create_analysis(ecosystem, package, version, force=True)

        return {}, 202


class AnalysisByEPV(AnalysisBase):
    """This endpoint is intentionally "analysis", not "analyses". In API v1, it will
    always return 1 analysis, not more.
    """

    def get(self, ecosystem, package, version):
        package = urllib.parse.unquote(package)
        args = self._parse_args()
        projection = self._get_projection(args['fields'])

        result = get_latest_analysis_for(ecosystem, package, version)

        if not result:
            # NOTE: this won't force-create the analysis, meaning if an AnalysisRequest
            #  already exists, this will do nothing
            server_create_analysis(ecosystem, package, version)
            return {}, 202

        self._inc_access_counter(result)
        result = do_projection(projection, result)
        return self._sanitize_result(result, debuginfo=args['debuginfo'])


class AnalysisByHash(AnalysisBase):
    def get(self, algorithm, artifact_hash):
        args = self._parse_args()

        projection = self._get_projection(args['fields'])
        result = get_latest_analysis_by_hash(algorithm, artifact_hash, projection)

        if not result:
            # We don't know how to map hash to EPV, so we can't schedule new
            # analysis
            return {}, 404

        self._inc_access_counter(result)
        result = do_projection(projection, result)
        return self._sanitize_result(result, debuginfo=args['debuginfo'])


class AnalysisByID(AnalysisBase):
    """Retrieve a specific past analysis by its numeric ID"""
    def get(self, analysis_id):
        args = self._parse_args()

        projection = self._get_projection(args['fields'])
        try:
            result = Analysis.by_id(rdb.session, analysis_id)
        except NoResultFound:
            return {}, 404

        self._inc_access_counter(result)
        result = do_projection(projection, result)
        return self._sanitize_result(result, debuginfo=args['debuginfo'])


class ApiToken(ResourceWithSchema):
    method_decorators = [login_required]
    err = 'You have to be authenticated to {what} token'

    def _format_token(self):
        return {'token': current_user.token,
                'expires_at': current_user.token_expires.isoformat() if current_user.token_expires
                else None}

    def get(self):
        if current_user:
            return self._format_token()
        raise HTTPError(401, error=self.err.format(what='get'))

    def post(self):
        if current_user:
            current_user.generate_auth_token()
            # https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html says, that
            #  action performed by the POST method might not result in a resource that can be
            #  identified by a URI. In this case, either 200 (OK) or 204 (No Content) is the
            #  appropriate response status
            return self._format_token(), 200
        raise HTTPError(401, error=self.err.format(what='create new'))

    def delete(self):
        if current_user:
            current_user.revoke_auth_token()
            return self._format_token(), 200
        raise HTTPError(401, error=self.err.format(what='revoke'))


class User(ResourceWithSchema):
    method_decorators = [login_required]

    def get(self):
        ret = {}
        for attr in ['login', 'email', 'active', 'roles', 'token', 'token_expires']:
            ret[attr] = getattr(current_user, attr)
        return ret

class StackAnalysesByGraphGET(ResourceWithSchema):
    schema_ref = SchemaRef('stack_analyses', '2-1-4')

    def get(self, external_request_id):
        try:
            results = rdb.session.query(WorkerResult)\
                                 .filter(WorkerResult.external_request_id == external_request_id,
                                         or_(WorkerResult.worker == "stack_aggregator",WorkerResult.worker == "recommendation"))
            if results.count() <= 0:
                raise HTTPError(202, "Analysis for request ID '{t}' is in progress".format(t=external_request_id))
        except SQLAlchemyError:
            raise HTTPError(500, "Worker result for request ID '{t}' doesn't exist yet".format(t=external_request_id))

        try:
            recommendation_result = {}
            audit = ""
            external_request_id = ""
            manifest_response = []

            for row in results:
                result = row.to_dict()
                if result["worker"] == "stack_aggregator":
                    audit = result["task_result"]["_audit"]
                    external_request_id = result["external_request_id"]
                    manifest_response.append(result["task_result"])
                else:
                    recommendation_result = {"recommendations": result["task_result"]["recommendations"]}

            response = {
                "started_at": audit["started_at"],
                "finished_at": audit["ended_at"],
                "request_id": external_request_id,
                "result": manifest_response,
                "recommendation": recommendation_result
            }
            return response
        except:
            raise HTTPError(500, "Error creating response for request {t}".format(t=external_request_id))
 

class StackAnalysesByGraph(ResourceWithSchema):
    schema_ref = SchemaRef('stack_analyses', '2-1-4')
    def post(self):
        session = FuturesSession()
        files = request.files.getlist('manifest[]')
        dt = datetime.datetime.now()
        origin = request.form.get('origin')
        
        # At least one manifest file should be present to analyse a stack
        if len(files) <= 0:
            return jsonify( error="Error processing request. Please upload a valid manifest files.")
        
        request_id = uuid.uuid4().hex
        manifests = []
        stack_data = {}
        result = []
        for f in files:
            filename = f.filename
            
            # check if manifest files with given name are supported
            manifest_descriptor = get_manifest_descriptor_by_filename(filename)
            if manifest_descriptor is None:
                return jsonify (error="Manifest file '{filename}' is not supported".format(filename=filename))
            
            content = f.read().decode('utf-8')
            
            # In memory file to be passed as an API parameter to /appstack
            manifest_file = StringIO(content)
            
            # Check if the manifest is valid
            if not manifest_descriptor.validate(content):
                return jsonify(error="Error processing request. Please upload a valid manifest file '{filename}'".
                               format(filename=filename))
            
            # Limitation: Currently, appstack can support only package.json
            # Record the response details for this manifest file
            manifest = {'filename': filename, 'content': content, 'ecosystem': manifest_descriptor.ecosystem}
            manifests.append(manifest)
            if 'package.json' in filename:
                substr = []
                # Read package contents
                packagejson = json.loads(content)
                appstack_file = {'packagejson': manifest_file}
                url = current_app.config["BAYESIAN_ANALYTICS_URL"]
                analytics_url = "{analytics_baseurl}/api/v1.0/recommendation".format(analytics_baseurl=url)
                                                
                urls = [analytics_url,current_app.config["GREMLIN_SERVER_URL_REST"]]
                # call recommendation api asynchronously
                try:
                    reco_req = session.post(urls[0],files=appstack_file, timeout=None)
                except Exception as exc:
                    current_app.logger.warn("Analytics query: {}".format(exc))
                # carry on with further processing
                for pkg, ver in packagejson['dependencies'].items():
                    substr.append("has('pecosystem','NPM').has('pname','" + pkg + "').has('version','" + ver + "')")
                substr1 = ",".join(substr)
                str_gremlin = "g.V().or(" + substr1 + ").valueMap(true);"
                payload = {'gremlin': str_gremlin}
                # call graph endpoint to fetch attributes asynchronously
                graph_req = session.post(urls[1],data=json.dumps(payload))
                #wait for all request to process

                graph_resp = graph_req.result()
                stack_data = aggregate_stack_data(graph_resp.json(),filename, "npm") #Hardcoded to NPM
                #Get Recommendation API result
                reco_resp = reco_req.result()
                reco_json= reco_resp.json()
                stack_data['recommendation'] = reco_json
                result.append(stack_data)

        # Store the Request in DB
        try:
            req = StackAnalysisRequest(id=request_id, submitTime=str(dt), requestJson={'manifest': manifests}, 
                                       origin=origin, result={'result': result})
            rdb.session.add(req)
            rdb.session.commit()
        except SQLAlchemyError:
            current_app.logger.exception('Failed to create new analysis request')
            raise HTTPError(500, "Error inserting log for request {t}".format(t=request_id))
        
        response = {'status': 'success',
                    'request_id': request_id,
                    'result':result}
        return (response)

class ComponentsInRange(ResourceWithSchema):
    schema_ref = SchemaRef('version_range_resolver', '1-0-0')

    def get(self,  ecosystem):
        query = request.args.get('q')
        eco = Ecosystem.by_name(rdb.session, ecosystem)
        fetcher = CucosReleasesFetcher(eco, rdb.session)
        now = datetime.datetime.now()

        # Instantiate two different solvers, one using a custom fetcher to fetch
        # matching releases from Bayesian DB and the other one fetching from
        # upstream repositories.
        # The data from these two solvers then provide information as to:
        #   1) Which packages in the range we have already analysed and have information
        #        about
        #   2) Other packages from upstream repositories which match the version specification
        cucos_solver, solver = get_ecosystem_solver(eco, with_fetcher=fetcher),\
                               get_ecosystem_solver(eco)

        ours = cucos_solver.solve([query], all_versions=True)
        upstream = solver.solve([query], all_versions=True)

        ours_nums = set() if not ours else set(next(iter(ours.values())))
        upstreams_nums = set() if not upstream else set(next(iter(upstream.values())))

        return {'query': query, 'detail': {'analysed': ours, 
                                           'upstream': upstream, 
                                           'difference': list(upstreams_nums - ours_nums)},
                                'resolved_at': str(now)}


class UserFeedback(ResourceWithSchema):
    _ANALYTICS_BUCKET_NAME = "{DEPLOYMENT_PREFIX}-".format(**os.environ) \
                             + os.environ.get("AWS_ANALYTICS_BUCKET", "bayesian-user-feedback")

    def post(self):
        input_json = request.get_json()

        if not request.json or 'request_id' not in input_json:
            raise HTTPError(400, error="Expected JSON request")

        if 'recommendation' not in input_json or 'name' not in input_json['recommendation']:
            raise HTTPError(400, error="Expected field name in recommendation")

        s3 = AmazonS3(bucket_name=self._ANALYTICS_BUCKET_NAME)
        s3.connect()
        # Store data
        key = "{}-{}".format(input_json["request_id"], input_json["recommendation"]["name"])
        s3.store_dict(input_json, key)

        return {'status': 'success'}


class StackAnalyses(ResourceWithSchema):
    def post(self):
        files = request.files.getlist('manifest[]')
        dt = datetime.datetime.now()
        origin = request.form.get('origin')

        # At least one manifest file should be present to analyse a stack
        if len(files) <= 0:
            raise HTTPError(400, error="Error processing request. Please upload a valid manifest files.")

        request_id = uuid.uuid4().hex
        manifests = []
        ecosystem = None
        for f in files:
            filename = f.filename

            # check if manifest files with given name are supported
            manifest_descriptor = get_manifest_descriptor_by_filename(filename)
            if manifest_descriptor is None:
                raise HTTPError(400, error="Manifest file '{filename}' is not supported".format(filename=filename))

            content = f.read().decode('utf-8')

            # In memory file to be passed as an API parameter to /appstack
            manifest_file = StringIO(content)

            # Check if the manifest is valid
            if not manifest_descriptor.validate(content):
                raise HTTPError(400, error="Error processing request. Please upload a valid manifest file '{filename}'".format(filename=filename))

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
                        appstack_id = resp.get('appstack_id','')
                    else:
                        current_app.logger.warn("{status}: {error}".format(status=response.status_code, error=response.content))

            # Record the response details for this manifest file
            manifest = {'filename': filename, 'content': content, 'ecosystem': manifest_descriptor.ecosystem}
            if appstack_id != '':
                manifest['appstack_id'] = appstack_id

            manifests.append(manifest)

        #Insert in a single commit. Gains - a) performance, b) avoid insert inconsistencies for a single request
        try:
            req = StackAnalysisRequest(id=request_id, submitTime=str(dt), requestJson={'manifest': manifests}, origin=origin)
            rdb.session.add(req)
            rdb.session.commit()
        except SQLAlchemyError:
            current_app.logger.exception('Failed to create new analysis request')
            raise HTTPError(500, "Error inserting log for request {t}".format(t=request_id))

        try:
            args = {'external_request_id': request_id, 'manifest': manifests, 'ecosystem': ecosystem}
            server_run_flow('stackApiGraphFlow', args)
        except:
            # Just log the exception here for now
            current_app.logger.exception('Failed to schedule AggregatingMercatorTask for id {id}'.format(id=request_id))
            raise HTTPError(500, "Error processing request {t}. manifest files could not be processed".format(t=request_id))


        return {"status": "success", "submitted_at": str(dt), "id": str(request_id)}

    def get(self):
        try:
            results = rdb.session.query(StackAnalysisRequest)\
                                 .order_by(StackAnalysisRequest.submitTime.desc())
            results_array = [result.to_dict() for result in results]
        except SQLAlchemyError:
            raise HTTPError(500,  "Error retrieving stack analyses")
        return {"status": "success", "results": results_array}


class StackAnalysesByOrigin(ResourceWithSchema):
    def get(self, origin):
        try:
            results = rdb.session.query(StackAnalysisRequest)\
                                 .filter(StackAnalysisRequest.origin == origin)\
                                 .order_by(StackAnalysisRequest.submitTime.desc())
            results_array = [result.to_dict() for result in results]
        except SQLAlchemyError:
            raise HTTPError(500,  "Error retrieving stack analyses")
        return {"status": "success", "results": results_array}


class StackAnalysesById(ResourceWithSchema):
    schema_ref = SchemaRef('stack_analyses', '2-1-3')

    def get(self, external_request_id):
        submitted_at = ""
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
                if manifest.get('appstack_id',0):
                    manifest_appstackid_map[manifest["filename"]] = manifest["appstack_id"]

        except SQLAlchemyError:
            raise HTTPError(500, "Error fetching data for request ID '{id}'".format(id=external_request_id))

        try:
            results = rdb.session.query(WorkerResult)\
                                 .filter(WorkerResult.external_request_id == external_request_id,
                                         WorkerResult.worker == "dependency_aggregator")
            if results.count() <= 0:
                raise HTTPError(202, "Analysis for request ID '{t}' is in progress".format(t=external_request_id))
        except SQLAlchemyError:
            raise HTTPError(500, "Worker result for request ID '{t}' doesn't exist yet".format(t=external_request_id))

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
                        component["relative_usage"] = usage_rank2str(get_component_percentile_rank(component["ecosystem"],
                                                                                                   component["name"],
                                                                                                   component["version"],
                                                                                                   rdb.session))
                    manifest_appstack_id = manifest_appstackid_map.get(manifest["manifest_name"],'')
                    if manifest_appstack_id != '':
                        url = current_app.config['BAYESIAN_ANALYTICS_URL']
                        endpoint = "{analytics_baseurl}/api/v1.0/recommendation/{appstack_id}".format(analytics_baseurl=url,appstack_id=manifest_appstack_id)
                        resp = requests.get(endpoint)
                        if resp.status_code == 200:
                            recommendation = resp.json()

                            # Adding URI of the stacks to the recommendation
                            if recommendation.get("input_stack",{}).get("appstack_id","") != "":
                                recommendation["input_stack"]["uri"] = "{analytics_baseurl}/api/v1.0/appstack/{appstack_id}".format(analytics_baseurl=url,appstack_id=recommendation["input_stack"]["appstack_id"])

                            if recommendation.get("recommendations",{}).get("similar_stacks","") != "":
                                for r in recommendation["recommendations"]["similar_stacks"]:
                                    if r["stack_id"] != "":
                                        r["uri"] = "{analytics_baseurl}/api/v1.0/appstack/{appstack_id}".format(analytics_baseurl=url,appstack_id=r["stack_id"])
                            manifest["recommendation"] = recommendation
                        else:
                            current_app.logger.warn("{status}: {error}".format(status=resp.status_code, error=resp.content))

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
        except:
            raise HTTPError(500, "Error creating response for request {t}".format(t=external_request_id))


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
add_resource_no_matter_slashes(Ecosystems, '/ecosystems')
add_resource_no_matter_slashes(Packages, '/packages/<ecosystem>')
add_resource_no_matter_slashes(Versions, '/versions/<ecosystem>/<package>')
add_resource_no_matter_slashes(ComponentsInRange, '/versions/in-range/<ecosystem>')
add_resource_no_matter_slashes(AnalysesEPVByGraph, '/component-analyses/<ecosystem>/<package>/<version>',
                                endpoint='get_component_analysis')
add_resource_no_matter_slashes(Analyses, '/analyses')
add_resource_no_matter_slashes(AnalysisByHash, '/analyses/by-artifact-hash/<algorithm>/<artifact_hash>',
                               endpoint='get_analysis_by_hash')
add_resource_no_matter_slashes(AnalysisByEPV, '/analyses/<ecosystem>/<package>/<version>',
                               endpoint='get_analysis')
add_resource_no_matter_slashes(AnalysisByID, '/analyses/by-id/<int:analysis_id>',
                               endpoint='get_analysis_by_id')
add_resource_no_matter_slashes(ApiToken, '/api-token')
add_resource_no_matter_slashes(User, '/user')
add_resource_no_matter_slashes(SystemVersion, '/system/version')
add_resource_no_matter_slashes(StackAnalyses, '/stack-analyses')
add_resource_no_matter_slashes(StackAnalysesByGraphGET, '/stack-analyses/<external_request_id>')
add_resource_no_matter_slashes(StackAnalysesByOrigin, '/stack-analyses/by-origin/<origin>')
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
