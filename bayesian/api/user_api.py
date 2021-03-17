"""Definition of all REST API endpoints for user management."""
import uuid

from flask import Blueprint, request
from flask.json import jsonify

from fabric8a_auth.auth import login_required
from fabric8a_auth.errors import AuthError
from f8a_utils.user_token_utils import is_snyk_token_valid, encrypt_api_token, UserStatus

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

    user_status = UserStatus.FREETIER.name
    user = user_utils.get_user(user_id)
    if user:
        user_status = user.status if user.status else UserStatus.FREETIER.name
        return jsonify(user_id=user_id, status=user_status)
    else:
        return jsonify(message='User not found', status=404), 404


@user_api.route('', methods=['POST'])
@login_required
def generate_uuid_for_user():
    """Endpoint for creating user details."""
    user_uuid = uuid.uuid4()
    return jsonify(user_id=user_uuid)


@user_api.route('', methods=['PUT'])
@login_required
def create_or_update_user():
    """Endpoint for creating or updating user details."""
    content = request.json
    if not content:
        return jsonify(message='User ID and Snyk Token should be present', status=400), 400

    user_id = content.get('user_id')

    if not user_id:
        return jsonify(message='User ID should be present', status=400), 400

    snyk_api_token = content.get('snyk_api_token')
    if not snyk_api_token:
        return jsonify(message='Snyk API Token should be present', status=400), 400

    if not is_snyk_token_valid(snyk_api_token):
        return jsonify(message='Snyk API Token is invalid', status=400), 400

    encrypted_api_token = encrypt_api_token(snyk_api_token)
    user_utils.create_or_update_user(user_id, encrypted_api_token.decode(), "SNYK")
    return jsonify(user_id=user_id)


@user_api.errorhandler(AuthError)
def handle_authorization_error(e):
    """Exception handler for handling authorization errors."""
    return jsonify(message='Authentication failed', status=e.status_code), 401


@user_api.errorhandler(UserException)
def handle_user_exception(e):
    """Exception handler for handling user management errors."""
    return jsonify(message=e.message, status='500'), 500
