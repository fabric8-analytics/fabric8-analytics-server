# Copyright © 2020 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""Test Utility."""


from bayesian.v2.utility import VendorAnalyses, ResponseBuilder
from urllib.parse import quote
from unittest.mock import patch
import os
import json


def get_vendor_data(vendor):
    """Read Vendor Data from JSON."""
    vendor_obj = {
        'snyk': 'snyk_component_analyses_response.json'
    }
    rest_json_path = os.path.join(
        os.path.dirname(__file__),
        'data/gremlin/{}'.format(vendor_obj[vendor])
    )
    with open(rest_json_path) as f:
        resp_json = json.load(f)
    return resp_json


@patch("bayesian.utils.post")
@patch("bayesian.utils.generate_recommendation")
def test_graph_analyses(gr_mocker, post_mocker):
    """Test Vendor Analyses Class for Integration."""
    snyk_data = get_vendor_data('snyk')
    post_mocker.return_value = MockedGremlinResponse(snyk_data)
    gr_mocker.return_value = GenerateRecommendationMocker(snyk_data).clubbed_data()
    graph_analyses_obj = VendorAnalyses(
        'maven', 'com.fasterxml.jackson.core:jackson-databind', '2.8.9')
    response = graph_analyses_obj.get_vendor_analyses()
    assert response is None


class MockedGremlinResponse:
    """Mock Gremlin Response."""

    def __init__(self, data):
        """Intialize class with Snyk data."""
        self.data = data

    def json(self):
        """Mock Json Call."""
        return self.data


class GenerateRecommendationMocker:
    """Mock Response Object for Generate Recommendation Function."""

    def __init__(self, resp):
        """Intialize constructor with response data obj."""
        self.resp = resp

    def clubbed_data(self):
        """Generate Json Response for Recommendation Mocker."""
        return {
            "epv": self.resp['result'].get('data'),
            "recommended_versions": self.resp['result'].get('data')[0]['cve']['sfixed_in']
        }


def test_get_link():
    """Test link to vendor website."""
    link = ResponseBuilder(
        'maven', 'com.fasterxml.jackson.core:jackson-databind', '2.8.9').get_link()
    assert link == "https://snyk.io/vuln/maven:" + quote(
        "com.fasterxml.jackson.core:jackson-databind")
