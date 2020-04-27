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


from bayesian.v2.utility import VendorAnalyses, ResponseBuilder, Adequacy
from urllib.parse import quote
from unittest.mock import patch
import os
import json
import unittest


def get_vendor_data(vendor):
    """Read Vendor Data from JSON."""
    vendor_obj = {
        'snyk': 'snyk_component_analyses_response.json'
    }
    rest_json_path = os.path.join(
        os.path.dirname(__file__),
        '../data/gremlin/{}'.format(vendor_obj[vendor])
    )
    with open(rest_json_path) as f:
        resp_json = json.load(f)
    return resp_json


def test_get_link():
    """Test link to vendor website."""
    link = ResponseBuilder(
        'maven', 'com.fasterxml.jackson.core:jackson-databind', '2.8.9').get_link()
    assert link == "https://snyk.io/vuln/maven:" + quote(
        "com.fasterxml.jackson.core:jackson-databind")


class AdequacyTest(unittest.TestCase):
    """Test Cases for Adequacy Utility class."""

    @staticmethod
    def test_version_info_tuple():
        """Test function for version info tuple."""
        version_str = "2.0.rc1"
        package_name = "test_package"
        version_obj = Adequacy.convert_version_to_proper_semantic(version_str, package_name)
        version_info = Adequacy.version_info_tuple(version_obj)
        assert len(version_info) == 4
        assert version_info[0] == version_obj.major
        assert version_info[1] == version_obj.minor
        assert version_info[2] == version_obj.patch
        assert version_info[3] == version_obj.build

    @staticmethod
    def test_version_info_tuple_negative():
        """Test function for convert version to tuple."""
        version_info = Adequacy.version_info_tuple('version')
        assert len(version_info) == 4

    @staticmethod
    def test_convert_version_to_proper_semantic():
        """Test function for convert version to proper semantic."""
        version_obj = Adequacy.convert_version_to_proper_semantic("", 'package')
        assert 0 == version_obj.major
        assert 0 == version_obj.minor
        assert 0 == version_obj.patch

    @staticmethod
    def test_convert_version_to_proper_semantic_exception():
        """Test function for convert version to proper semantic."""
        version_obj = Adequacy.convert_version_to_proper_semantic("THROW")
        assert 0 == version_obj.major
        assert 0 == version_obj.minor
        assert 0 == version_obj.patch


class VendorAnalysesTest(unittest.TestCase):
    """Test Cases for Vendor Analyses Test class."""

    @staticmethod
    def test_is_package_known_with_None():
        """Test function when package query returns None."""
        result = VendorAnalyses("eco", "pkg", "ver").is_package_known(None)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_empty_query():
        """Test function when package query returns empty."""
        result = VendorAnalyses("eco", "pkg", "ver").is_package_known({})
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_missing_data():
        """Test function when package query returns empty."""
        query = dict(result={})
        result = VendorAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_empty_data():
        """Test function when package query returns empty."""
        query = dict(result=dict(data={}))
        result = VendorAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_actual_data():
        """Test Function for known package info."""
        query = dict(result=dict(data=["random"]))
        result = VendorAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is True

    @staticmethod
    @patch('bayesian.v2.communicator.GraphAnalyses.get_data_from_graph', return_value=None)
    def test_get_vendor_analyses(_mock1):
        """Test Function for vendor analyses."""
        analyses = VendorAnalyses('eco', 'pkg', 'ver').get_vendor_analyses()
        assert analyses is None

    @staticmethod
    @patch('bayesian.v2.utility.ResponseBuilder.generate_recommendation', return_value="kuchbhi")
    @patch('bayesian.v2.utility.VendorAnalyses.is_package_known', return_value=True)
    @patch('bayesian.v2.communicator.GraphAnalyses.get_data_from_graph', return_value="kuchbhi")
    def test_get_vendor_analyses_response_builder(_graphmock, _known_pkgmock, _responsemock):
        """Test function for vendor analyses response builder."""
        analyses = VendorAnalyses('eco', 'pkg', 'ver').get_vendor_analyses()
        assert analyses == 'kuchbhi'

    @staticmethod
    @patch('bayesian.v2.communicator.GraphAnalyses.get_data_from_graph', return_value=Exception)
    def test_get_vendor_analyses_response_builder_exception(_graphmock):
        """Generates exception. Test Exception Block."""
        analyses = VendorAnalyses('eco', 'pkg', 'ver').get_vendor_analyses()
        assert analyses is None


class ResponseBuilderTest(unittest.TestCase):
    """Test Cases for Response Builder."""

    graph_response = dict(result=dict(data=[{}]))

    @classmethod
    def setUpClass(self):
        """Class variables initialised."""
        self.ecosystem = 'ecosystem'
        self.version = '1'
        self.package = 'package'
        self._cves = list()
        self.cve_dict = dict()
        self.severity = ""
        self.nocve_version = ""
        self.public_vul = 0
        self.pvt_vul = 0

    def test_generate_recommendation(self):
        """Test Function for Generate recommendation."""
        response = ResponseBuilder('eco', 'pkg', 'ver').generate_recommendation(self.graph_response)
        assert response == dict(recommendation={})

    def test_generate_recommendation_same_version(self):
        """Test Function for Generate recommendation_same_version."""
        graph_response = dict(result=dict(data=[{'version': {'version': ['1']}, 'cve': 'cve'}]))
        # response = ResponseBuilder('eco', 'pkg', 'ver').generate_recommendation(graph_response)
        result_data = graph_response.get('result', {}).get('data')
        for data in result_data:
            this_version = data.get('version', {}).get('version', [None])[0]
            if this_version == self.version:
                if 'cve' in data:
                    self._cves.append(data.get('cve'))

        # self.assertEqual(response, "response")
        # assert response == dict(recommendation={})
