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
        with patch('bayesian.api.user_api.user_utils') as user_utils_mock:
            response = self.client.get('/user/03ec8318-08ed-4aeb-8305-2d5827fd0f72')
            user_utils_mock.get_user.assert_called_once()
            assert response.status_code == 200

    def test_user_put_false(self):
        """Test case for PUT user."""
        with patch('bayesian.api.user_api.user_utils') as user_utils_mock_put:
            with patch('bayesian.api.user_api.request') as request:
                request.json.return_value = {'user_id': '123', 'snyk_api_token': 'abc'}
                user_utils_mock_put.is_snyk_token_valid.return_value = False

                with(pytest.raises(HTTPError)):
                    user_api.create_or_update_user()

    def test_user_put(self):
        """Test case for PUT user."""
        with patch('bayesian.api.user_api.user_utils') as user_utils_mock_put:
            with patch('bayesian.api.user_api.request') as request:
                request.json.return_value = {'user_id': '123', 'snyk_api_token': 'abc'}
                user_utils_mock_put.is_snyk_token_valid.return_value = True

                response = self.client.put('/user')

                user_utils_mock_put.encrypt_api_token.assert_called_once()
                user_utils_mock_put.create_or_update_user.assert_called_once()
                assert response.status_code == 200

    def test_user_post(self):
        """Test case for POST user."""
        with patch('bayesian.api.user_api.uuid') as uuid_mock:
            response = self.client.post('/user')
            uuid_mock.uuid4.assert_called_once()
            assert response.status_code == 200
