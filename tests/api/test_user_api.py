"""Test Case for User API."""
import pytest
from unittest.mock import patch

from f8a_worker.models import (UserDetails)

from bayesian.api import user_api
from bayesian.exceptions import HTTPError
from bayesian.utility import user_utils


def get_user_function(uuid):
    """User details required in the fixture."""
    user_details = UserDetails()
    user_details.user_id = uuid
    user_details.snyk_api_token = None
    return user_details


@pytest.fixture
def get_user_details(monkeypatch):
    """Fixture for returning user details."""
    monkeypatch.setattr(user_utils, 'get_user', get_user_function)


@pytest.mark.usefixtures('client_class', 'get_user_details')
class TestUserEndpoints:
    """Test case for testing the endpoints."""

    def test_user_get(self):
        """Test case for GET user."""
        response = self.client.get('/user/03ec8318-08ed-4aeb-8305-2d5827fd0f72')
        assert response.status_code == 200

    def test_user_put(self):
        """Test case for PUT user."""
        with patch('bayesian.api.user_api.user_utils') as user_utils_mock_put:
            with patch('bayesian.api.user_api.request') as request:
                user_utils_mock_put.update_user.side_effect = None
                request.json.side_effect = None
                response = self.client.put('/user/03ec8318-08ed-4aeb-8305-2d5827fd0f72')

                user_utils_mock_put.update_user.assert_called_once()
                assert response.status_code == 200

    def test_user_post(self):
        """Test case for POST user."""
        with patch('bayesian.api.user_api.user_utils') as user_utils_mock:
            user_utils_mock.create_user.side_effect = None
            response = self.client.post('/user')

            user_utils_mock.create_user.assert_called_once()
            assert response.status_code == 200


@pytest.mark.usefixtures('get_user_details')
class TestUserApiFunctions:
    """Test case for testing the API functions."""

    def test_get_user_with_no_user_id(self):
        """Test case for testing the API functions."""
        with pytest.raises(HTTPError):
            user_api.get_user(None)
