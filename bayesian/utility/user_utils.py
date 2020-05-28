"""Definition of all utility and db interactions for user management."""
import datetime
import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import insert, update

from f8a_worker.models import (UserDetails)
from bayesian import rdb

logger = logging.getLogger(__file__)


def get_user(uuid_val):
    """Get User."""
    try:
        query = rdb.session.query(UserDetails).filter(UserDetails.user_id == uuid_val)
        user = query.one()
        return user
    except SQLAlchemyError:
        rdb.session.rollback()
        logger.exception(f"Error fetching user with id {uuid_val}")
        raise UserException("Error fetching user")


def create_user(uuid_val, user_source):
    """Create User."""
    try:
        insert_user_stmt = insert(UserDetails).values(user_id=uuid_val, user_source=user_source,
                                                      created_date=datetime.datetime.now())

        rdb.session.execute(insert_user_stmt)
        rdb.session.commit()
        logger.info(f"User created with id {uuid_val}")
    except SQLAlchemyError:
        rdb.session.rollback()
        logger.exception("Error creating new user")
        raise UserException("Error creating user")


def update_user(user_id, snyk_api_token):
    """Update User."""
    try:
        update_stmt = update(UserDetails).where(UserDetails.user_id == user_id).values(
            dict(snyk_api_token=snyk_api_token, updated_date=datetime.datetime.now(),
                 registered_date=datetime.datetime.now()))

        rdb.session.execute(update_stmt)
        rdb.session.commit()
        logger.info(f"User updated with id {user_id}")
    except SQLAlchemyError:
        rdb.session.rollback()
        logger.exception(f"Error updating user with id {user_id}")
        raise UserException("Error updating user")


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message

    def __str__(self):
        """Representation of the exception."""
        return self.message
