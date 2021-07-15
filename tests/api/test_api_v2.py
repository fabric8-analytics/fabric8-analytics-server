"""Test APIs v2."""

import os
import io
import json
import pytest
import unittest
from pathlib import Path
from unittest.mock import patch
from bayesian.utility.db_gateway import RDBSaveException, RDBInvalidRequestException
from bayesian.utility.v2.backbone_server import BackboneServerException
from bayesian.utility.v2.sa_response_builder import (SARBRequestInvalidException,
                                                     SARBRequestInprogressException,
                                                     SARBRequestTimeoutException)
from bayesian.utility.v2.component_analyses import Package


def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v2' + route


@pytest.mark.usefixtures('client_class')
class TestCommonEndpoints():
    """Basic tests for several endpoints."""

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


@pytest.mark.usefixtures('client_class')
class TestCAPostApi(unittest.TestCase):
    """Component Analyses Unit Tests."""

    @classmethod
    def setUpClass(cls) -> None:
        """Init Test class."""
        gremlin_batch_data = os.path.join('tests/data/gremlin/gremlin_batch_data.json')
        recommendation_data = os.path.join('tests/data/response/ca_batch_response.json')

        with open(gremlin_batch_data) as f:
            cls.gremlin_batch_data = json.load(f)

        with open(recommendation_data) as f:
            cls.recommendation_data = json.load(f)

    @patch('bayesian.api.api_v2.create_component_bookkeeping')
    @patch('bayesian.api.api_v2.add_unknown_pkg_info')
    @patch('bayesian.api.api_v2.unknown_package_flow')
    @patch('bayesian.api.api_v2.get_batch_ca_data')
    def test_get_component_analyses_post(self, _mock1, _mock2, _mock3, _mock4):
        """CA POST: Valid API."""
        test = [{"package": "markdown2", "version": "2.3.2", "package_unknown": False}]
        _mock1.return_value = self.gremlin_batch_data
        _mock3.return_value = test
        payload = {
            "ecosystem": 'pypi',
            "package_versions": [
                {"package": "markdown2", "version": "2.3.2"}
            ]
        }
        accept_json = [('Content-Type', 'application/json;')]
        response = self.client.post(
            api_route_for('/component-analyses'), data=json.dumps(payload), headers=accept_json)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, self.recommendation_data)

    @patch('bayesian.api.api_v2.create_component_bookkeeping')
    @patch('bayesian.api.api_v2.add_unknown_pkg_info')
    @patch('bayesian.api.api_v2.get_known_unknown_pkgs')
    @patch('bayesian.api.api_v2.unknown_package_flow')
    @patch('bayesian.api.api_v2.get_batch_ca_data')
    def test_get_component_analyses_unknown_flow(self, _mock1, _mock2,
                                                 _mock3, _mock4, _mock5):
        """CA POST: Unknown Flow."""
        test = [{"package": "django", "version": "1.1", "package_unknown": True}]
        _mock1.return_value = self.gremlin_batch_data
        unknown_pkgs = set()
        unknown_pkgs.add(Package(package='django', given_name='django', version='1.1',
                                 given_version='1.1', is_pseudo_version=False,
                                 package_unknown=True))
        _mock3.return_value = self.recommendation_data, unknown_pkgs
        _mock4.return_value = test
        payload = {
            "ecosystem": 'pypi',
            "package_versions": [
                {"package": "markdown2", "version": "2.3.2"}
            ]
        }
        accept_json = [('Content-Type', 'application/json;')]
        response = self.client.post(
            api_route_for('/component-analyses'), data=json.dumps(payload), headers=accept_json)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json, test)

    def test_get_component_analyses_bad_request(self):
        """CA POST: Bad Request."""
        payload = {
            "ecosys": 'pypi',
            "package_versions": [
                {"package": "markdown2", "version": "2.3.2"}
            ]
        }
        accept_json = [('Content-Type', 'application/json;')]
        response = self.client.post(
            api_route_for('/component-analyses'), data=json.dumps(payload), headers=accept_json)
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(
            response.json,
            {'error': '400 Bad Request: Ecosystem None is not supported for this request'})


@pytest.mark.usefixtures('client_class')
class TestVAPostApi(unittest.TestCase):
    """Vulnerability Analysis Unit Tests."""

    @classmethod
    def setUpClass(cls) -> None:
        """Init Test class."""
        gremlin_batch_data = os.path.join('tests/data/gremlin/gremlin_batch_data.json')
        recommendation_data = os.path.join('tests/data/response/ca_batch_response.json')

        with open(gremlin_batch_data) as f:
            cls.gremlin_batch_data = json.load(f)

        with open(recommendation_data) as f:
            cls.recommendation_data = json.load(f)

    @patch('bayesian.api.api_v2.get_batch_ca_data')
    def test_get_vulnerability_analysis_post(self, _mock1, _mock2, _mock3, _mock4):
        """VA POST: Valid API."""
        test = [{"package": "markdown2", "version": "2.3.2"}]
        _mock1.return_value = self.gremlin_batch_data
        _mock3.return_value = test
        payload = {
            "ecosystem": 'pypi',
            "package_versions": [
                {"package": "markdown2", "version": "2.3.2"}
            ]
        }
        accept_json = [('Content-Type', 'application/json;')]
        response = self.client.post(
            api_route_for('/vulnerability-analysis'), data=json.dumps(payload), headers=accept_json)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, self.recommendation_data)

    def test_get_vulnerability_analysis_bad_request(self):
        """VA POST: Bad Request."""
        payload = {
            "ecosys": 'pypi',
            "package_versions": [
                {"package": "markdown2", "version": "2.3.2"}
            ]
        }
        accept_json = [('Content-Type', 'application/json;')]
        response = self.client.post(
            api_route_for('/vulnerability-analysis'), data=json.dumps(payload), headers=accept_json)
        self.assertEqual(response.status_code, 400)
        self.assertDictEqual(
            response.json,
            {'error': '400 Bad Request: Ecosystem None is not supported for this request'})

@pytest.mark.usefixtures('client_class')
class TestGetTokenApi(unittest.TestCase):
    """Get Token Unit Tests."""

    def test_get_token_request_success(self):
        """Test success get token request."""
        response = self.client.get(api_route_for('/get-token'))
        self.assertEqual(response.status_code, 200)

    def test_get_token_request_invalid_url(self):
        """Test get token request data with return as 404 error."""
        response = self.client.get(api_route_for('/get-token/mathur/07'))
        self.assertEqual(response.status_code, 404)

    def test_get_token_request_with_slash(self):
        """Test get token request data with return as 404 error for invalid url."""
        response = self.client.get(api_route_for('/get-token/'))
        self.assertEqual(response.status_code, 404)

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

    def test_sa_post_invalid_ecosystem_and_manifest(self):
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

    def test_sa_post_invalid_manifest_file_content(self):
        """Post request with invalid manifest file content. Expecting http error 400."""
        data = {
            'manifest': (io.StringIO(str(Path(__file__).parent /
                                         '../data/manifests/400/npmlist.json')).read(),
                         'pylist.json'),
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

    def test_sa_post_manifest_ecosystem_mismatch(self):
        """Success post request with all valid data."""
        data = self.post_data
        data['ecosystem'] = 'pypi'
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
