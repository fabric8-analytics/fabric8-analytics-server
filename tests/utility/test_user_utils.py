"""Test Case for User Management Utilities."""
import pytest
from bayesian.utility.user_utils import UserException
from bayesian.utility import user_utils


@pytest.fixture
def create_user(rdb):
    """Fixture that creates a user which is used on other tests."""
    assert rdb
    user_utils.create_user('03ec8318-08ed-4aeb', 'SNYK')


@pytest.mark.usefixtures('rdb')
class TestUserUtils:
    """Test cases for user management utilities."""

    @pytest.mark.usefixtures('create_user')
    def test_get_user(self):
        """Test case for get user."""
        user = user_utils.get_user('03ec8318-08ed-4aeb')
        assert user.user_source == 'SNYK'

    @pytest.mark.usefixtures('create_user')
    def test_get_user_not_found(self):
        """Test case for get user not found."""
        with pytest.raises(UserException):
            user_utils.get_user('uuid')

    def test_create_user(self):
        """Test case for create user."""
        user_utils.create_user('03ec8318-08ed-4aeb', 'SNYK')
        assert user_utils.get_user('03ec8318-08ed-4aeb').user_id == '03ec8318-08ed-4aeb'

    @pytest.mark.usefixtures('create_user')
    def test_update_user(self):
        """Test case for update user."""
        user_utils.update_user('03ec8318-08ed-4aeb', '03ec8318')
        assert user_utils.get_user('03ec8318-08ed-4aeb').snyk_api_token == '03ec8318'
