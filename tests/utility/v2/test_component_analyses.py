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
#
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""Test Component Analyses Utility Stand."""
import json
import os
import unittest
from unittest.mock import patch

from werkzeug.exceptions import BadRequest

from bayesian.utility.v2.component_analyses import validate_version, \
    known_package_flow, ca_validate_input, get_known_unknown_pkgs, normlize_packages


class TestComponentAnalyses(unittest.TestCase):
    """Test Component Analyses Utility class."""

    @classmethod
    def setUpClass(cls) -> None:
        """Init Test class."""
        batch_data_no_cve = os.path.join('/bayesian/tests/data/gremlin/batch_data_no_cve.json')

        with open(batch_data_no_cve) as f:
            cls.gremlin_batch_data_no_cve = json.load(f)

    def test_validate_version(self):
        """Test Version should not contain special Characters."""
        result = validate_version("1.1")
        self.assertTrue(result)

    def test_validate_version_false(self):
        """Test Version should not contain special Characters."""
        result = validate_version("1.*")
        self.assertFalse(result)

    @patch('bayesian.utility.v2.component_analyses.g')
    @patch('bayesian.utility.v2.component_analyses.server_create_component_bookkeeping')
    def test_known_package_flow(self, _mock1, _mock2):
        """Test get package version."""
        _mock1.return_value = True
        result = known_package_flow('pypi', "django", "1.1")
        self.assertTrue(result)

    @patch('bayesian.utility.v2.component_analyses.g')
    @patch('bayesian.utility.v2.component_analyses.server_create_component_bookkeeping')
    def test_get_known_unknown_pkgs_no_cve(self, _mock1, _mock2):
        """Test Known Unknown Pkgs, No Cve."""
        normalised_input_pkgs = [normlize_packages('markdown2', "2.3.2", "2.3.2")]
        batch_data_no_cve = os.path.join('/bayesian/tests/data/gremlin/batch_data_no_cve.json')
        with open(batch_data_no_cve) as f:
            gremlin_batch_data_no_cve = json.load(f)

        stack_recommendation, unknown_pkgs = get_known_unknown_pkgs(
            "pypi", gremlin_batch_data_no_cve, normalised_input_pkgs)
        ideal_output = [{'package': 'markdown2',
                         'version': '2.3.2',
                         'package_unknown': False,
                         'recommendation': {}}]
        self.assertListEqual(stack_recommendation, ideal_output)
        self.assertSetEqual(unknown_pkgs, set())

    @patch('bayesian.utility.v2.ca_response_builder.g')
    @patch('bayesian.utility.v2.component_analyses.g')
    @patch('bayesian.utility.v2.component_analyses.server_create_component_bookkeeping')
    def test_get_known_unknown_pkgs_with_and_without_cve(self, _mock1, _mock2, _mock3):
        """Test Known Unknown Pkgs, with and Without CVE."""
        input_pkgs = [('flask', "1.1.1", "1.1.1"), ('django', "1.1.1", "1.1.1")]
        normalised_input_pkgs = [normlize_packages(pkg, vr, gvn_vr)
                                 for pkg, vr, gvn_vr in input_pkgs]
        batch_data_no_cve = os.path.join(
            '/bayesian/tests/data/gremlin/batch_data_with_n_without_cve.json')
        with open(batch_data_no_cve) as f:
            data_with_n_without_cve = json.load(f)

        ideal_resp = os.path.join(
            '/bayesian/tests/data/response/ca_batch_with_n_without_vul.json')
        with open(ideal_resp) as f:
            ideal_output = json.load(f)

        stack_recommendation, unknown_pkgs = get_known_unknown_pkgs(
            "pypi", data_with_n_without_cve, normalised_input_pkgs)

        self.assertListEqual(stack_recommendation, ideal_output)
        self.assertSetEqual(unknown_pkgs, set())


class TestCAInputValidator(unittest.TestCase):
    """Test Input Validator."""

    def test_ca_validate_input_exception(self):
        """Test Ca Validate input: Missing Input."""
        self.assertRaises(BadRequest, ca_validate_input, None, "pypi")

    def test_ca_validate_input_invalid_type(self):
        """Test Ca Validate input: Invalid Input type."""
        self.assertRaises(BadRequest, ca_validate_input, [""], "pypi")

    def test_ca_validate_input_invalid_ecosystem(self):
        """Test Ca Validate input: Invalid Input type."""
        self.assertRaises(BadRequest, ca_validate_input, {"test": "test"}, "madam")

    def test_ca_validate_input_no_pkg_version(self):
        """Test Ca Validate input: Invalid Input."""
        self.assertRaises(BadRequest, ca_validate_input, {"test": "test"}, "pypi")

    def test_ca_validate_input_pkg_missing_details(self):
        """Test Ca Validate input: Package Version Missing Details."""
        input_json = {
            "ecosystem": "pypi",
            "package_versions": [
                {"no_package": "markdown2", "no_version": "2"},
            ]
        }
        self.assertRaises(BadRequest, ca_validate_input, input_json, "pypi")

    def test_ca_validate_input_pkg_invalid_type(self):
        """Test Ca Validate input: Package Type."""
        input_json = {
            "ecosystem": "pypi",
            "package_versions": [
                {"package": {"Test": "Test"}, "version": "2.3.2"},
            ]
        }
        self.assertRaises(BadRequest, ca_validate_input, input_json, "pypi")

    def test_ca_validate_input_pkg_version_invalid_version(self):
        """Test Ca Validate input: Version Invalid version."""
        input_json = {
            "ecosystem": "pypi",
            "package_versions": [
                {"package": "markdown2", "version": "2.*"},
            ]
        }
        ecosystem = "pypi"
        self.assertRaises(BadRequest, ca_validate_input, input_json, ecosystem)

    def test_ca_validate_input_maven(self):
        """Test Ca Validate input: Ecosystem maven."""
        input_json = {
            "ecosystem": "maven",
            "package_versions": [
                {"package": "com.thoughtworks.xstream:xstream", "version": "1.3"},
            ]
        }
        ideal_result = [
            {"name": "com.thoughtworks.xstream:xstream", "version": "1.3", "given_version": "1.3"}]
        result, _ = ca_validate_input(input_json, input_json["ecosystem"])
        self.assertEqual(result, ideal_result)
