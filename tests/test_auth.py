"""Tests for classes and functions from the auth module."""
from unittest.mock import Mock, patch

from bayesian.auth import validate_user
import unittest


# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):   # NOQA
    """Request Mocker."""

    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if args[0] == 'http://someurl.com/test.json':
        return MockResponse({"key1": "value1"}, 200)
    elif args[0] == 'http://someotherurl.com/anothertest.json':
        return MockResponse({"key2": "value2"}, 200)

    return MockResponse(None, 404)


class TestAuth(unittest.TestCase):
    """Test Namespace."""

    @patch('requests.get', side_effect=mocked_requests_get)
    @patch('bayesian.utility.user_utils.get_user')
    def test_validate_user(self, _mock1, _mock2):
        """Test Decorator validate_user."""
        _mock1.return_value = None
        m1 = Mock
        result = validate_user(m1)
        self.assertIsInstance(result, object)
