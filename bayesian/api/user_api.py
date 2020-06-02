"""Definition of all REST API endpoints for user management."""
import uuid

from flask import Blueprint, request
from flask.json import jsonify

from fabric8a_auth.auth import login_required
from fabric8a_auth.errors import AuthError

from bayesian.exceptions import HTTPError
from bayesian.utility import user_utils
from bayesian.utility.user_utils import UserException

user_api = Blueprint('user_api', __name__, url_prefix='/user')


@user_api.route('/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """Endpoint for getting user details."""
    if not user_id:
        raise HTTPError(400, "user id should be present")

    user = user_utils.get_user(user_id)
    return jsonify(user_id=user.user_id, status=user.status)


@user_api.route('', methods=['POST'])
@login_required
def create_user():
    """Endpoint for creating user details."""
    user_uuid = uuid.uuid4()
    user_utils.create_user(user_uuid, "SNYK")
    return jsonify(user_id=user_uuid)


@user_api.route('/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Endpoint for updating user details."""
    if not user_id:
        raise HTTPError(400, "user id should be present")

    content = request.json
    user_utils.update_user(user_id, content['snyk_api_token'])
    return jsonify(user_id=user_id)


@user_api.errorhandler(AuthError)
def handle_authorization_error(e):
    """Exception handler for handling authorization errors."""
    return jsonify(message='Authentication failed', status=e.status_code), 401


@user_api.errorhandler(UserException)
def handle_user_exception(e):
    """Exception handler for handling user management errors."""
    return jsonify(message=e.message, status='500'), 500
