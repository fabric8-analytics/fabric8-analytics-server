"""Definition of all REST API endpoints of the server module."""

import logging
from flask import Blueprint, request
from flask.json import jsonify
from flask_restful import Api, Resource
from sqlalchemy.exc import SQLAlchemyError
from f8a_worker.models import (Ecosystem, RecommendationFeedback)
from . import rdb
from fabric8a_auth.auth import login_required
from .exceptions import HTTPError
from .utils import (get_system_version, is_valid,)
from fabric8a_auth.errors import AuthError

logger = logging.getLogger(__name__)

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
    logger.debug('Liveness probe - trying to connect to database and execute a query')
    rdb.session.query(Ecosystem).count()
    return jsonify({}), 200


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
            logger.exception('Failed to create new analysis request')
            raise HTTPError(
                500, "Error inserting log for request {t}".format(t=stack_id)) from e


add_resource_no_matter_slashes(ApiEndpoints, '')
add_resource_no_matter_slashes(SubmitFeedback, '/submit-feedback')
add_resource_no_matter_slashes(SystemVersion, '/system/version')


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
def api_404_handler():
    """Handle all other routes not defined above."""
    return jsonify(error='Cannot match given query to any API v1 endpoint'), 404
