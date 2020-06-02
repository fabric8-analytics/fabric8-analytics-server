"""Definition of all utility and db interactions for user management."""
import datetime
import logging
from enum import Enum
import tenacity
from tenacity import retry

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import insert, update

from f8a_worker.models import (UserDetails)
from bayesian import rdb

logger = logging.getLogger(__file__)


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def get_user(uuid_val):
    """Get User."""
    try:
        result = rdb.session.query(UserDetails).filter(UserDetails.user_id == uuid_val)
        user = result.one()
        return user
    except SQLAlchemyError as e:
        logger.exception(f"Error fetching user with id {uuid_val}")
        raise UserException("Error fetching user") from e


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def create_user(uuid_val, user_source):
    """Create User."""
    try:
        insert_user_stmt = insert(UserDetails).values(user_id=uuid_val, user_source=user_source,
                                                      created_date=datetime.datetime.now())

        rdb.session.execute(insert_user_stmt)
        rdb.session.commit()
        logger.info(f"User created with id {uuid_val}")
    except SQLAlchemyError as e:
        rdb.session.rollback()
        logger.exception("Error creating new user")
        raise UserException("Error creating user") from e


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def update_user(user_id, snyk_api_token):
    """Update User."""
    try:
        if snyk_api_token:
            update_stmt = update(UserDetails).where(UserDetails.user_id == user_id).values(
                dict(snyk_api_token=snyk_api_token, updated_date=datetime.datetime.now(),
                     status=UserStatus.REGISTERED.name, registered_date=datetime.datetime.now()))

        rdb.session.execute(update_stmt)
        rdb.session.commit()
        logger.info(f"User updated with id {user_id}")
    except SQLAlchemyError as e:
        rdb.session.rollback()
        logger.exception(f"Error updating user with id {user_id}")
        raise UserException("Error updating user") from e


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message
        super().__init__(message)


class UserStatus(Enum):
    """Enumeration for maintaining user status."""

    REGISTERED = 1
