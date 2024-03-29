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
from bayesian.settings import ENABLE_USER_CACHING
from bayesian import rdb
import os
import requests
import json

_JOB_API_URL = "http://{host}:{port}/internal/ingestions".format(
    host=os.environ.get("JOB_SERVICE_HOST", "bayesian-jobs"),
    port=os.environ.get("JOB_SERVICE_PORT", "34000"),)

logger = logging.getLogger(__name__)


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def get_user(uuid_val):
    """Get User."""
    try:
        result = rdb.session.query(UserDetails).filter(UserDetails.user_id == uuid_val)
        user = result.one()
        return user
    except NoResultFound:
        logger.info("User not found with id %s", uuid_val)
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


def create_or_update_user_in_cache(user_id):
    """Create or Update User in cache."""
    if ENABLE_USER_CACHING:
        try:
            url = _JOB_API_URL + "/create_or_update_user_in_cache"
            requests.request("POST", url,
                             data=json.dumps({"user_id": user_id}),
                             headers={"Content-Type": "application/json"})
        except Exception as e:
            logger.exception("Error while caching user with id %s", user_id)
            raise UserException("Error caching user") from e


def get_user_from_cache(user_id):
    """Get User from cache."""
    try:
        url = _JOB_API_URL + "/get-user-details/" + user_id
        response = requests.request("GET", url)
        return response.json()
    except Exception as e:
        logger.info("Failed to find user in cache with id %s", user_id)
        logger.error(e)
        return None


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message
        super().__init__(message)
