"""Authorization token handling."""
import logging
from functools import wraps
from flask import g, request
from pydantic.error_wrappers import ValidationError
from bayesian.utility.user_utils import get_user, UserException
from bayesian.utility.v2.sa_models import HeaderData
from bayesian.exceptions import HTTPError
from f8a_utils.user_token_utils import UserStatus

logger = logging.getLogger(__name__)


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
        try:
            header_data = HeaderData(uuid=request.headers.get('uuid', None))
            if header_data.uuid:
                g.uuid = str(header_data.uuid)
                user = get_user(g.uuid)
                if user:
                    g.user_status = UserStatus[user.status]
        except ValidationError as e:
            raise HTTPError(400, "Not a valid uuid") from e
        except UserException:
            logger.warning("Unable to get user status for uuid '{}'".format(header_data.uuid))

        logger.debug('For UUID: %s, got user type: %s final uuid: %s',
                     header_data.uuid, g.user_status, g.uuid)
        return view(*args, **kwargs)

    return wrapper
