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
import json
import os

logger = logging.getLogger(__name__)
DB_CACHE_DIR = os.environ.get("DB_CACHE_DIR")
ENABLE_USER_CACHING = os.environ.get('ENABLE_USER_CACHING', 'true') == 'true'


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


def create_or_update_user_in_cache(user_id, snyk_api_token, user_source):
    """Create or Update User in cache."""
    if ENABLE_USER_CACHING:
        db_cache_file_path = DB_CACHE_DIR + "/" + user_id + ".json"
        user_detail = {"user_id": user_id,
                       "user_source": user_source,
                       "snyk_api_token": snyk_api_token,
                       "status": UserStatus.REGISTERED.name,
                       "created_date": datetime.datetime.now(),
                       "registered_date": datetime.datetime.now()}
        try:
            with open(db_cache_file_path, 'w', encoding='utf-8') as file:
                json.dump(user_detail, file, ensure_ascii=False, indent=4, default=str)

            logger.info("User added in cache with id %s", user_id)
        except Exception as e:
            logger.exception("Error while caching user with id %s", user_id)
            raise UserException("Error caching user") from e


def get_user_from_cache(user_id):
    """Get User from cache."""
    user = {}
    try:
        db_cache_file_path = DB_CACHE_DIR + "/" + user_id + ".json"

        if os.path.isfile(db_cache_file_path):
            logger.info("Found user in cache with id %s", user_id)
            file = open(db_cache_file_path, "r")
            user = json.loads(file.read())
        return user
    except Exception as e:
        logger.info("User not found in cache with id %s", user_id)
        logger.error(e)
        return None


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message
        super().__init__(message)
