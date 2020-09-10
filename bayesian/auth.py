"""Authorization token handling."""
import logging
from functools import wraps
from flask import g, request
from requests import get
from pydantic.error_wrappers import ValidationError
from bayesian.utility.user_utils import get_user, UserStatus, UserException, UserNotFoundException
from bayesian.utility.v2.sa_models import HeaderData
from bayesian.exceptions import HTTPError

from .default_config import AUTH_URL


logger = logging.getLogger(__name__)


def get_access_token(service_name):
    """Return the access token for service."""
    services = {'github': 'https://github.com'}
    url = '{auth_url}/api/token?for={service}'.format(
        auth_url=AUTH_URL, service=services.get(service_name))
    token = request.headers.get('Authorization')
    headers = {"Authorization": token}
    try:
        _response = get(url, headers=headers)
        if _response.status_code == 200:
            response = _response.json()
            return {"access_token": response.get('access_token')}
        else:
            return {"access_token": None}

    except Exception:
        logger.error('Unable to connect to Auth service')


def validate_user(view):
    """Validate and get user type based on UUID from the request."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        """Read uuid and decides user type based on its validity."""
        # Rule of UUID validation and setting user status ::
        #  ==============================================================
        #   UUID in request | UUID in RDS | RDS User State | User Status
        #  ==============================================================
        #    MISSING        | -- NA --    | -- NA --       | FREE
        #    PRESENT        | MISSING     | -- NA --       | FREE
        #    PRESENT        | PRESENT     | REGISTERED     | REGISTERED
        #    PRESENT        | PRESENT     | !REGISTERED    | FREE
        #  ==============================================================

        # By default set this to 'freetier' and uuid to None
        g.user_status = UserStatus.FREETIER
        g.uuid = None
        header_data = HeaderData(uuid=request.headers.get('uuid', None))
        try:
            if header_data.uuid:
                g.uuid = str(header_data.uuid)
                user = get_user(g.uuid)
                g.user_status = UserStatus[user.status]
        except ValidationError as e:
            raise HTTPError(400, "Not a valid uuid") from e
        except UserNotFoundException:
            logger.warning("Invalid UUID {}".format(header_data.uuid))
        except UserException:
            logger.warning("Unable to get user status for uuid '{}'".format(header_data.uuid))

        logger.debug('For UUID: %s, got user type: %s final uuid: %s',
                     header_data.uuid, g.user_status, g.uuid)
        return view(*args, **kwargs)

    return wrapper
