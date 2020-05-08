"""Test APIs v2."""

import pytest
from bayesian.api.api_v2 import ApiEndpoints, ComponentAnalysesApi, _session
import unittest
from unittest.mock import patch, Mock
from bayesian.exceptions import HTTPError
import os


def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v2' + route


class TestApiEndpoints(unittest.TestCase):
    """Test APIEnpoints Register Class."""

    @classmethod
    def setUp(cls):
        """Initialise class with required params."""
        cls._resource_paths = ['a', 'b']

    def test_get(self):
        """Test Get method of API Endpoints."""
        result = ApiEndpoints().get()
        self.assertIsInstance(result, dict)
        self.assertIn('paths', result)


@pytest.mark.usefixtures('client_class')
class TestCommonEndpoints():
    """Basic tests for several endpoints."""

    def test_readiness(self, accept_json):
        """Test the /readiness endpoint."""
        res = self.client.get(api_route_for('/readiness'), headers=accept_json)
        assert res.status_code == 200

    def test_liveness(self, accept_json):
        """Test the /liveness endpoint."""
        res = self.client.get(api_route_for('/liveness'), headers=accept_json)
        assert res.status_code == 200

    def test_system_version(self, accept_json):
        """Test the /system/version endpoint."""
        responese = self.client.get(api_route_for('/system/version'), headers=accept_json)
        assert responese.status_code == 200

    def test_error_exception(self, accept_json):
        """Test the /error endpoint. Direct Access."""
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
        assert response.status_code == 404

    def test_error_status_401(self, accept_json, monkeypatch):
        """Test the /error endpoint. Function Redirect."""
        monkeypatch.setenv("REDIRECT_STATUS", '401')
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
        assert response.status_code == 401
        monkeypatch.delenv("REDIRECT_STATUS", raising=False)

    def test_error_status_405(self, accept_json, monkeypatch):
        """Test the /error endpoint. Function Redirect."""
        monkeypatch.setenv("REDIRECT_STATUS", '405')
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
        monkeypatch.delenv("REDIRECT_STATUS", raising=False)
        assert response.status_code == 405

    def test_get_component_analyses_invalid_package(self, accept_json, monkeypatch):
        """Test Component Analyses get. Invalid Package."""
        monkeypatch.setattr(_session, 'post', Mock)
        response = self.client.get(
            api_route_for('/component-analyses/maven/package/2.7.5'), headers=accept_json)
        monkeypatch.delattr(_session, 'post')
        assert response.json == {'error': 'Invalid maven format - package'}

    def test_get_component_analyses_unknown_ecosystem(self, accept_json):
        """CA GET: Invalid Ecosystem."""
        response = self.client.get(
            api_route_for('/component-analyses/unknown/package/version'), headers=accept_json)
        assert response.json == {'error': 'Ecosystem unknown is not supported for this request'}


class TestComponentAnalysesApi(unittest.TestCase):
    """Component Analyses Unit Tests."""

    @patch('bayesian.api.api_v2.g')
    @patch('bayesian.api.api_v2._session')
    @patch('bayesian.api.api_v2.server_create_component_bookkeeping')
    @patch('bayesian.api.api_v2.server_create_analysis')
    @patch('bayesian.api.api_v2.request')
    @patch('bayesian.api.api_v2.case_sensitivity_transform')
    def test_get_component_analyses(self, _sensitive, _request,
                                    _analyses, _bookkeeping, _session, _g):
        """CA GET: No Analyses Data found, without INVOKE_API_WORKERS flag, Raises HTTP Error."""
        ca = ComponentAnalysesApi()
        self.assertRaises(HTTPError, ca.get, "npm", "pkg", "ver")

    @patch('bayesian.api.api_v2.g')
    @patch('bayesian.api.api_v2._session')
    @patch('bayesian.api.api_v2.server_create_component_bookkeeping')
    @patch('bayesian.api.api_v2.server_create_analysis')
    @patch('bayesian.api.api_v2.request')
    @patch('bayesian.api.api_v2.case_sensitivity_transform')
    @patch('bayesian.api.api_v2.ComponentAnalyses.get_vendor_analyses', return_value=None)
    def test_get_component_analyses_with_invoke_api_workers(
            self, _vendor, _sensitive, _request, _analyses, _bookkeeping, _session, _g):
        """CA GET: No Analyses Data found with API worker flag."""
        ca = ComponentAnalysesApi()
        with patch.dict('os.environ', {'INVOKE_API_WORKERS': '1'}):
            response = ca.get("npm", "pkg", "ver")
            self.assertEqual(response.status, 202)
            self.assertIsInstance(response, tuple)
        self.assertNotIn('INVOKE_API_WORKERS', os.environ)

    @patch('bayesian.api.api_v2.g')
    @patch('bayesian.api.api_v2._session')
    @patch('bayesian.api.api_v2.server_create_component_bookkeeping')
    @patch('bayesian.api.api_v2.server_create_analysis')
    @patch('bayesian.api.api_v2.request')
    @patch('bayesian.api.api_v2.case_sensitivity_transform')
    @patch('bayesian.api.api_v2.ComponentAnalyses.get_vendor_analyses')
    def test_get_component_analyses_with_result_not_none(
            self, _vendor_analyses, _sensitive, _request, _analyses, _bookkeeping, _session, _g):
        """CA GET: with VALID result."""
        result = 'my_package_analyses_result'
        _vendor_analyses.return_value = result
        ca = ComponentAnalysesApi()
        analyses_result = ca.get("npm", "pkg", "ver")
        self.assertEqual(analyses_result, result)
