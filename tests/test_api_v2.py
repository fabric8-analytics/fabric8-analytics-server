"""Unit tests for the REST API module."""
from f8a_worker.utils import (MavenCoordinates)
from unittest.mock import Mock
from bayesian.v2.utility import VendorAnalyses
from unittest.mock import patch
from bayesian.v2 import api_v2
import json
from fabric8a_auth.errors import AuthError
import unittest


def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v2' + route

class MyCustomError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

class TestApiV1Root(object):
    """Basic tests if all endpoints are accessible."""

    api_root = {
        "paths": [
            "/api/v2",
            "/api/v2/component-analyses/<ecosystem>/<package>/<version>",
            "/api/v2/system/version"
        ]
    }

    def test_api_root(self, accept_json, client):
        """Basic tests if all endpoints are accessible."""
        res = client.get(api_route_for('/'), headers=accept_json)
        assert res.status_code == 200
        assert res.json == self.api_root


class TestCommonEndpoints(object):
    """Basic tests for several endpoints."""
    def test_readiness(self, accept_json, client):
        """Test the /readiness endpoint."""
        res = client.get(api_route_for('/readiness'), headers=accept_json)
        assert res.status_code == 200

    def test_liveness(self, accept_json, client):
        """Test the /liveness endpoint."""
        res = client.get(api_route_for('/liveness'), headers=accept_json)
        assert res.status_code == 200 or res.status_code == 500

    def test_error(self, accept_json, client):
        """Test the /_error endpoint."""
        res = client.get(api_route_for('/_error'), headers=accept_json)
        assert res.status_code == 404

    def test_system_version(self, accept_json, client):
        """Test the /system/version endpoint."""
        res = client.get(api_route_for('/system/version'), headers=accept_json)
        assert res.status_code == 200

    def test_component_analyses(self, accept_json, client):
        """Test the /component-analyses endpoint for GET."""
        res = client.get(api_route_for('/component-analyses/abb/cc/dd'),
                              headers=accept_json)
        assert res.status_code == 400

    def test_component_analyses1(self, client):
        print("Calling test_component_analyses1")
        """Test the /component-analyses endpoint for POST."""
        data = [
            {
                "ecosystem": "pypi",
                "package": "pandas",
                "version": "1.0.0"
            }
        ]
        res = client.post(api_route_for('/component-analyses'),
                               data=json.dumps(data),
                               content_type='application/json')
        assert res.status_code == 405


    @patch('f8a_worker.utils.case_sensitivity_transform')
    #@patch('bayesian.v2.utility.VendorAnalyses.get_vendor_analyses', return_value=None)
    def test_component_analyses1(self, accept_json, client):
        #res = client.get(api_route_for('/component-analyses/maven/com.fasterxml.jackson.core:jackson-databind/2.7.5'),headers=accept_json)
        #assert res.status_code == 400
        res = api_v2.ComponentAnalyses.get("maven", "com.fasterxml.jackson.core:jackson-databind", "2.7.5")
        assert res is None


class TestApiV1SystemVersion():
    """Tests for the /api/v1/system/version endpoint."""

    def test_get_system_version(self, accept_json, client):
        """Test for the /api/v1/system/version endpoint."""
        res = client.get(api_route_for('/system/version/'), headers=accept_json)
        assert res.status_code == 200
        assert set(res.json.keys()) == {'committed_at', 'commit_hash'}


@patch('bayesian.v2.communicator.GraphAnalyses.get_data_from_graph', return_value = None)
def test_get_vendor_analyses(_mock1):
    analysis = VendorAnalyses("maven", "com.fasterxml.jackson.core:jackson-databind", "2.7.5").get_vendor_analyses()
    assert analysis is None


def test_normalize_str():
    package = 'com.fasterxml.jackson.core:jackson-databind'
    package_result = MavenCoordinates.normalize_str(package)
    assert package_result == 'com.fasterxml.jackson.core:jackson-databind'


#def test_api_401_handler():
#    err = AuthError()
#    res = api_v2.api_401_handler(err)
#    assert res != None


#def test_api_404_handler():
#    api_v2 = Mock()
#    api_v2.api_404_handler.return_value = None
#    res = api_v2.api_404_handler()
#    assert res is None


#@patch('f8a_worker.utils.case_sensitivity_transform')
#def test_case_sensitivity_transform():
    #package_result = api_v2.case_sensitivity_transform()
    #assert package_result is None

#@patch('bayesian.exceptions.HTTPError')
#@patch('bayesian.v2.api_v2.api_401_handler', return_value=None)
#def test_api_401_handler(self):
#    res = api_v2.api_401_handler(HTTPError)
#    assert res == None

#@patch('bayesian.exceptions.HTTPError')
#@patch('bayesian.v2.api_v2.api_404_handler', return_value = None)
#def test_api_404_handler(self):
#    res = api_v2.api_404_handler(HTTPError)
#    assert res == None

#@patch('f8a_worker.utils.case_sensitivity_transform', return_value = Exception)
#def test_case_sensitivity_transform(self):
#    package_result = api_v2.case_sensitivity_transform()
#    assert package_result == None

