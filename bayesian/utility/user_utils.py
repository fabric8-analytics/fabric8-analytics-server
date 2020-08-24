"""Definition of all utility and db interactions for user management."""
import datetime
import logging
from enum import Enum
import tenacity
from tenacity import retry
import requests
from cryptography.fernet import Fernet

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from f8a_worker.models import (UserDetails)
from bayesian import rdb
from bayesian.default_config import SNYK_API_TOKEN_VALIDATION_URL, ENCRYPTION_KEY_FOR_SNYK_TOKEN

logger = logging.getLogger(__name__)


@retry(reraise=True, stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(1))
def get_user(uuid_val):
    """Get User."""
    try:
        result = rdb.session.query(UserDetails).filter(UserDetails.user_id == uuid_val)
        user = result.one()
        return user
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
                                                  updated_date=datetime.datetime.now()))
        rdb.session.execute(do_update_stmt)
        rdb.session.commit()
        logger.info("User added with id %s", user_id)
    except SQLAlchemyError as e:
        rdb.session.rollback()
        logger.exception("Error updating user with id %s", user_id)
        raise UserException("Error updating user") from e


@retry(reraise=True, stop=tenacity.stop_after_attempt(6),
       wait=tenacity.wait_exponential(multiplier=2, min=4))
def is_snyk_token_valid(snyk_api_token):
    """Validate Snyk API token."""
    try:
        response = requests.post(SNYK_API_TOKEN_VALIDATION_URL, json={'api': snyk_api_token})
        return response.status_code == 200
    except Exception as e:
        logger.exception("Encountered exception calling Snyk")
        raise e


def encrypt_api_token(snyk_api_token):
    """Encryption of Api Token."""
    cipher = Fernet(ENCRYPTION_KEY_FOR_SNYK_TOKEN.encode())
    return cipher.encrypt(snyk_api_token.encode())


def decrypt_api_token(snyk_api_token):
    """Decryption of Api Token."""
    cipher = Fernet(ENCRYPTION_KEY_FOR_SNYK_TOKEN.encode())
    return cipher.decrypt(snyk_api_token.encode())


class UserException(Exception):
    """Exception for all User Management."""

    def __init__(self, message):
        """Initialize the exception."""
        self.message = message
        super().__init__(message)


class UserStatus(Enum):
    """Enumeration for maintaining user status."""

    REGISTERED = 1
    FREETIER = 2
    EXPIRED = 3
