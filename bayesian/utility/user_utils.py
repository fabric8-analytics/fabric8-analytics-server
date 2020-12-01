"""Definition of all utility and db interactions for user management."""
import datetime
import logging
import tenacity
from tenacity import retry

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.dialects.postgresql import insert

from f8a_worker.models import (UserDetails)
from f8a_utils.user_token_utils import UserStatus
from bayesian import rdb

logger = logging.getLogger(__name__)


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def get_user(uuid_val):
    """Get User."""
    try:
        result = rdb.session.query(UserDetails).filter(UserDetails.user_id == uuid_val)
        user = result.one()
        return user
    except NoResultFound:
        logger.exception("User not found with id %s", uuid_val)
        return None
    except SQLAlchemyError as e:
        logger.exception("Error fetching user with id %s", uuid_val)
        raise UserException("Error fetching user") from e


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def create_or_update_user(user_id, snyk_api_token, user_source):
    """Create or Update User."""
    try:
        insert_user_stmt = insert(UserDetails).values(user_id=user_id, user_source=user_source,
                                                      snyk_api_token=snyk_api_token,
                                                      created_date=datetime.datetime.now(),
                                                      status=UserStatus.REGISTERED.name,
                                                      registered_date=datetime.datetime.now())

        do_update_stmt = insert_user_stmt.on_conflict_do_update(
            index_elements=['user_id'], set_=dict(snyk_api_token=snyk_api_token,
                                                  status=UserStatus.REGISTERED.name,
                                                  updated_date=datetime.datetime.now(),
                                                  registered_date=datetime.datetime.now()))
        rdb.session.execute(do_update_stmt)
        rdb.session.commit()
        logger.info("User added with id %s", user_id)
    except SQLAlchemyError as e:
        rdb.session.rollback()
        logger.exception("Error updating user with id %s", user_id)
        raise UserException("Error updating user") from e


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message
        super().__init__(message)
