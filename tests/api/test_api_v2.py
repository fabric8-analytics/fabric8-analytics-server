"""Test APIs v2."""

import os
import io
import pytest
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
from bayesian.exceptions import HTTPError
from bayesian.api.api_v2 import _session, ApiEndpoints, ComponentAnalysesApi
from bayesian.utility.db_gateway import RDBSaveException, RDBInvalidRequestException
from bayesian.utility.v2.backbone_server import BackboneServerException
from bayesian.utility.v2.sa_response_builder import (SARBRequestInvalidException,
                                                     SARBRequestInprogressException,
                                                     SARBRequestTimeoutException)


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

    def test_get_component_analyses_invalid_version(self, accept_json, monkeypatch):
        """Test Component Analyses get. Invalid Version."""
        monkeypatch.setattr(_session, 'post', Mock)
        response = self.client.get(
            api_route_for('/component-analyses/maven/package/2.7.*'), headers=accept_json)
        monkeypatch.delattr(_session, 'post')
        assert response.json == {'error': "Package version should not have special characters."}

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
    def test_get_component_analyses_with_disable_unknown_package_flow(self, _sensitive, _request,
                                                                      _analyses, _bookkeeping,
                                                                      _session, _g):
        """No Analyses Data found, with DISABLE_UNKNOWN_PACKAGE_FLOW flag, returns 202."""
        with patch.dict('os.environ', {'DISABLE_UNKNOWN_PACKAGE_FLOW': '1'}):
            ca = ComponentAnalysesApi()
            response = ca.get('npm', 'pkg', 'ver')
            self.assertEqual(response.status, 202)
            self.assertIsInstance(response, tuple)

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


@pytest.mark.usefixtures('client_class')
class TestStackAnalysesGetApi(unittest.TestCase):
    """Stack Analyses Unit Tests."""

    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response',
           return_value='mock return value')
    def test_sa_get_request_success(self, _get_response):
        """Test success get request."""
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 200)

    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_invalid_request(self, _get_response):
        """Get request that is progress i.e., not yet completed."""
        expected_result = 'Stack analyses response for invalid request'
        _get_response.side_effect = SARBRequestInvalidException(expected_result)
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 400)

    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_progress(self, _get_response):
        """Get request that is progress i.e., not yet completed."""
        expected_result = 'Stack analyses response for inprogress request'
        _get_response.side_effect = SARBRequestInprogressException(expected_result)
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 202)

    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_timeout(self, _get_response):
        """Get request that is progress i.e., not yet completed."""
        expected_result = 'Stack analyses response for request timeout'
        _get_response.side_effect = SARBRequestTimeoutException(expected_result)
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 408)

    @patch('bayesian.api.api_v2.StackAnalysesResponseBuilder.get_response')
    def test_sa_get_request_error(self, _get_response):
        """Get request with 500 error."""
        _get_response.side_effect = RDBInvalidRequestException('Mock database error')
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 404)

    @patch('bayesian.utility.db_gateway.fetch_sa_request', side_effect=Exception('mock exception'))
    def test_get_request_data_exception(self, _fetch_sa_request):
        """Test get SA request data with return as 500 error."""
        response = self.client.get(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 500)

    def test_get_request_invalid_url(self):
        """Test get SA request data with return as 404 error."""
        response = self.client.get(api_route_for('/stack-analyses/request_id/sdf/dsfds'))
        self.assertEqual(response.status_code, 404)

    def test_get_request_missing_id(self):
        """Test get SA request data with return as 400 error for missing request id."""
        response = self.client.get(api_route_for('/stack-analyses'))
        self.assertEqual(response.status_code, 400)

    def test_get_request_with_slash(self):
        """Test get SA request data with return as 404 error for invalid url."""
        response = self.client.get(api_route_for('/stack-analyses/'))
        self.assertEqual(response.status_code, 404)


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

    def test_get_request_post(self):
        """Test get SA request data with return as 405 error."""
        response = self.client.post(api_route_for('/stack-analyses/request_id'))
        self.assertEqual(response.status_code, 405)

    def test_sa_post_missing_manifest_params(self):
        """Post request without manifest param. Expecting http error 400."""
        data = self.post_data
        del data['manifest']
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)

    def test_sa_post_empty_file_path(self):
        """Post request with empty file path. Expecting http error 400."""
        data = self.post_data
        data['file_path'] = ''
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

    def test_sa_post_invalid_manifest_file_content(self):
        """Post request with invalid manifest file content. Expecting http error 400."""
        data = {
            'manifest': (io.StringIO(str(Path(__file__).parent /
                                         '../data/manifests/400/npmlist.json')).read(),
                         'npmlist.json'),
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
    def test_sa_post_backbone_server_error(self, _post_request):
        """Success post request with all valid data."""
        _post_request.side_effect = BackboneServerException('mock exception')
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=self.post_data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 500)

    @patch('bayesian.api.api_v2.StackAnalyses.post_request')
    def test_sa_post_rdb_save_error(self, _post_request):
        """Success post request with all valid data."""
        _post_request.side_effect = RDBSaveException('mock exception')
        response = self.client.post(api_route_for('/stack-analyses'),
                                    data=self.post_data,
                                    content_type='multipart/form-data')
        self.assertEqual(response.status_code, 500)

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
