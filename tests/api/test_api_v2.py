"""Test APIs v2."""

import os
import io
import pytest
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from bayesian.exceptions import HTTPError
from bayesian.api.api_v2 import _session, ApiEndpoints, ComponentAnalysesApi, StackAnalysesApi


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
        response = self.client.get(api_route_for('/readiness'), headers=accept_json)
        assert response.status_code == 200

    def test_liveness(self, accept_json):
        """Test the /liveness endpoint."""
        response = self.client.get(api_route_for('/liveness'), headers=accept_json)
        assert response.status_code == 200

    def test_system_version(self, accept_json):
        """Test the /system/version endpoint."""
        response = self.client.get(api_route_for('/system/version'), headers=accept_json)
        assert response.status_code == 200

    def test_error_exception(self, accept_json):
        """Test the /error endpoint. Direct Access."""
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
        assert response.status_code == 404

    def test_error_status_401(self, accept_json, monkeypatch):
        """Test the /error endpoint. Function Redirect."""
        monkeypatch.setenv('REDIRECT_STATUS', '401')
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
        assert response.status_code == 401

    def test_error_status_405(self, accept_json, monkeypatch):
        """Test the /error endpoint. Function Redirect."""
        monkeypatch.setenv('REDIRECT_STATUS', '405')
        response = self.client.get(api_route_for('/_error'), headers=accept_json)
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
        self.assertRaises(HTTPError, ca.get, 'npm', 'pkg', 'ver')

    @patch('bayesian.api.api_v2.g')
    @patch('bayesian.api.api_v2._session')
    @patch('bayesian.api.api_v2.server_create_component_bookkeeping')
    @patch('bayesian.api.api_v2.server_create_analysis')
    @patch('bayesian.api.api_v2.request')
    @patch('bayesian.api.api_v2.case_sensitivity_transform')
    @patch('bayesian.utility.v2.ca_response_builder.'
           'ComponentAnalyses.get_component_analyses_response', return_value=None)
    def test_get_component_analyses_with_invoke_api_workers(
            self, _vendor, _sensitive, _request, _analyses, _bookkeeping, _session, _g):
        """CA GET: No Analyses Data found with API worker flag."""
        ca = ComponentAnalysesApi()
        with patch.dict('os.environ', {'INVOKE_API_WORKERS': '1'}):
            response = ca.get('npm', 'pkg', 'ver')
            self.assertEqual(response.status, 202)
            self.assertIsInstance(response, tuple)
        self.assertNotIn('INVOKE_API_WORKERS', os.environ)

    @patch('bayesian.api.api_v2.g')
    @patch('bayesian.api.api_v2._session')
    @patch('bayesian.api.api_v2.server_create_component_bookkeeping')
    @patch('bayesian.api.api_v2.server_create_analysis')
    @patch('bayesian.api.api_v2.request')
    @patch('bayesian.api.api_v2.case_sensitivity_transform')
    @patch('bayesian.utility.v2.ca_response_builder.'
           'ComponentAnalyses.get_component_analyses_response')
    def test_get_component_analyses_with_result_not_none(
            self, _vendor_analyses, _sensitive, _request, _analyses, _bookkeeping, _session, _g):
        """CA GET: with VALID result."""
        result = 'my_package_analyses_result'
        _vendor_analyses.return_value = result
        ca = ComponentAnalysesApi()
        analyses_result = ca.get('npm', 'pkg', 'ver')
        self.assertEqual(analyses_result, result)


class TestStackAnalysesGetApi(unittest.TestCase):
    """Stack Analyses Unit Tests."""

    @patch('bayesian.api.api_v2.RdbAnalyses.get_request_data', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_stack_result', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_recommendation_data', return_value={})
    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_success(self, _get_response, _recommendation_data, _stack_result,
                                    _request_data):
        """Test success get request."""
        expected_result = 'Stack analyses success response'
        _get_response.return_value = expected_result
        sa = StackAnalysesApi()
        response = sa.get('request_id')
        self.assertEqual(response, expected_result)

    @patch('bayesian.api.api_v2.RdbAnalyses.get_request_data', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_stack_result', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_recommendation_data', return_value={})
    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_progress(self, _get_response, _recommendation_data, _stack_result,
                                     _request_data):
        """Get request that is progress i.e., not yet completed."""
        expected_result = 'Stack analyses response for inprogress request'
        _get_response.side_effect = HTTPError(202, expected_result)
        sa = StackAnalysesApi()
        with pytest.raises(HTTPError) as http_error:
            sa.get('request_id')
        self.assertIs(http_error.type, HTTPError)
        self.assertEqual(http_error.value.code, 202)

    @patch('bayesian.api.api_v2.RdbAnalyses.get_request_data', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_stack_result', return_value={})
    @patch('bayesian.api.api_v2.RdbAnalyses.get_recommendation_data', return_value={})
    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_error(self, _get_response, _recommendation_data, _stack_result,
                                  _request_data):
        """Get request with 500 error."""
        _get_response.side_effect = HTTPError(500, 'Mock database error')
        sa = StackAnalysesApi()
        with pytest.raises(HTTPError) as http_error:
            sa.get('request_id')
        self.assertIs(http_error.type, HTTPError)
        self.assertEqual(http_error.value.code, 500)


@pytest.mark.usefixtures('client_class')
class TestStackAnalysesPostApi(unittest.TestCase):
    """Stack analyses post unit test cases."""

    def setUp(self):
        """Build post data that is required for each test case."""
        self.post_data = {
            'manifest': (io.StringIO(str(Path(__file__).parent /
                                         '../data/manifests/202/npmlist.json')).read(),
                         'npmlist.json'),
            'file_path': '/tmp/bin',
            'ecosystem': 'npm'
        }

    def test_sa_post_missing_manifest_params(self):
        """Post request without manifest param. Expecting http error 400."""
        data = self.post_data
        del data['manifest']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_invalid_manifest_file_name(self):
        """Post request with invalid manifest file name. Expecting http error 400."""
        data = {
            'manifest': (io.StringIO(str(Path(__file__).parent /
                                         '../data/manifests/202/npmlist.json')).read(),
                         'npmlist-invalid.json'),
            'file_path': '/tmp/bin',
            'ecosystem': 'pypi'
        }
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_missing_file_path(self):
        """Post request without file path param. Expecting http error 400."""
        data = self.post_data
        del data['file_path']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_invalid_file_path(self):
        """Post request with invalid file path value. Expecting http error 400."""
        data = self.post_data
        data['file_path'] = data['manifest']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_missing_ecosystem(self):
        """Post request without ecosystem param. Expecting http error 400."""
        data = self.post_data
        del data['ecosystem']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_invalid_ecosystem_type(self):
        """Post request with invalid ecosystem type. Expecting http error 400."""
        data = self.post_data
        data['ecosystem'] = data['manifest']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_invalid_ecosystem_value(self):
        """Post request with invalid ecosystem value. Expecting http error 400."""
        data = self.post_data
        data['ecosystem'] = 'ecosys_invalid'
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    @patch('bayesian.api.api_v2.StackAnalyses.post_request')
    def test_sa_post_success_200(self, _post_request):
        """Success post request with all valid data."""
        _post_request.return_value = {
            'status': 'success',
            'submitted_at': 'submitted_date_time',
            'id': 'dummy_id'
        }
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=self.post_data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json.get('status'), 'success')

    @patch('bayesian.api.api_v2.StackAnalyses.post_request')
    def test_sa_post_success_202(self, _post_request):
        """Success post request that returns 202."""
        expected_result = "This is mock success response with 202"
        _post_request.side_effect = HTTPError(202, expected_result)
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=self.post_data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json.get('error'), expected_result)

    @patch('bayesian.api.api_v2.StackAnalyses.post_request')
    def test_sa_post_error_500(self, _post_request):
        """Test error post request. Expecting http error 500."""
        expected_result = "This is mock error 500"
        _post_request.side_effect = HTTPError(500, expected_result)
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=self.post_data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json.get('error'), expected_result)
