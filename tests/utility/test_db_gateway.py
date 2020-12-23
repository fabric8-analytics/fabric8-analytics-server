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
# Author: Dharmendra G Patel <dhpatel@redhat.com>
#
"""Test DB Communicator."""

import os
import json
import pytest
import unittest
from unittest.mock import patch

from bayesian.utility.db_gateway import (GraphAnalyses, RdbAnalyses, RDBSaveException,
                                         RDBInvalidRequestException)
from sqlalchemy.exc import SQLAlchemyError


class GraphAnalysesTest(unittest.TestCase):
    """Test Communicator."""

    @classmethod
    def setUpClass(cls):
        """Class variables initialised."""
        cls.eco = 'eco'
        cls.ver = '1'
        cls.pkg = 'pkg'
        # Read Vendor Data from JSON.
        gremlin_batch_data = os.path.join('/bayesian/tests/data/gremlin/gremlin_batch_data.json')
        gremlin_vulnerabilities_data = os.path.join(
            '/bayesian/tests/data/gremlin/gremlin_vulnerabilities.json')
        gremlin_package_data = os.path.join('/bayesian/tests/data/gremlin/gremlin_packages.json')
        ca_batch_response = os.path.join('/bayesian/tests/data/response/ca_batch_response.json')

        with open(ca_batch_response) as f:
            cls.batch_response = json.load(f)

        with open(gremlin_batch_data) as f:
            cls.gremlin_batch = json.load(f)

        with open(gremlin_vulnerabilities_data) as f:
            cls.gremlin_vulnerabilities = json.load(f)

        with open(gremlin_package_data) as f:
            cls.gremlin_packages = json.load(f)

        # Read Vendor Data from JSON.
        rest_json_path2 = os.path.join(
            os.path.dirname(__file__),
            '..',
            'data/gremlin/snyk_component_analyses_response.json')
        with open(rest_json_path2) as f:
            resp_json = json.load(f)

        cls.resp_json = resp_json

    @patch('bayesian.utility.db_gateway.post')
    def test_get_data_from_graph(self, _mockpost):
        """Test Get data from Graph. Gremlin calls."""
        _mockpost().json.return_value = self.resp_json
        ga = GraphAnalyses.get_ca_data_from_graph('eco', 'pkg', 'ver', 'snyk')
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    @patch('bayesian.utility.db_gateway.post')
    def test_get_batch_ca_data(self, _mockpost):
        """Test get_batch_ca_data."""
        _mockpost().json.return_value = self.gremlin_batch
        ga = GraphAnalyses.get_batch_ca_data(
            ecosystem='eco', packages=[{'name': 'django', 'version': '1.1'}])
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    @patch('bayesian.utility.db_gateway.post', return_value=Exception)
    def test_get_batch_ca_data_exception(self, _mockpost):
        """Test get_batch_ca_data_exception."""
        self.assertRaises(Exception, GraphAnalyses.get_batch_ca_data,
                          'eco', packages=[{'name': 'django', 'version': '1.1'}],
                          query_key='ca_batch')

    @patch('bayesian.utility.db_gateway.post')
    def test_get_vulnerabilities_for_packages(self, _mockpost):
        """Test vulnerabilities query for packages from gremlin."""
        _mockpost().json.return_value = self.gremlin_vulnerabilities
        packages = [{
                'name': 'github.com/crda/test/package1',
                'version': 'v0.0.0-20180902000632-abcd4321dcba'
        }]
        ga = GraphAnalyses.get_vulnerabilities_for_packages('eco', packages)
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    @patch('bayesian.utility.db_gateway.post')
    def test_get_vulnerabilities_for_module(self, _mockpost):
        """Test vulnerabilities query for modules from gremlin."""
        _mockpost().json.return_value = self.gremlin_vulnerabilities
        packages = [{
                'name': 'github.com/crda/test',
                'version': 'v0.0.0-20160902000632-abcd4321dcba'
        }]
        ga = GraphAnalyses.get_vulnerabilities_for_packages('eco', packages)
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    @patch('bayesian.utility.db_gateway.post')
    def test_get_package_details(self, _mockpost):
        """Test package details query from gremlin."""
        _mockpost().json.return_value = self.gremlin_packages
        packages = [{
                'name': 'github.com/crda/test/package1',
                'version': 'v0.0.0-20180902000632-abcd4321dcba'
        }]
        ga = GraphAnalyses.get_package_details('eco', packages)
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    @patch('bayesian.utility.db_gateway.post')
    def test_get_module_package_data(self, _mockpost):
        """Test module details query from gremlin."""
        _mockpost().json.return_value = self.gremlin_packages
        packages = [{
                'name': 'github.com/crda/test',
                'version': 'v0.0.0-20160902000632-abcd4321dcba'
        }]
        ga = GraphAnalyses.get_package_details('eco', packages)
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)

    def test_filter_vulnerable_packages(self):
        """Test vuln filtering for module/packages."""
        vulnerabilities = self.gremlin_vulnerabilities.get('result', {}).get('data', [])
        package_version_map = {
            'github.com/crda/test': {'v0.0.0-20160902000632-abcd4321dcba': {}},
            'github.com/crda/test/package1': {'v0.0.0-20180902000632-abcd4321dcba': {}},
            'github.com/crda/test/package2': {'v0.0.0-20181002000632-abcd4321dcba': {}},
            'github.com/crda/test2': {'v0.0.0-20161002000632-abcd4321dcba': {}}
        }
        vuln = GraphAnalyses.filter_vulnerable_packages(vulnerabilities, package_version_map)
        self.assertIsInstance(vuln, dict)
        self.assertEqual(len(vuln), 2)
        self.assertIn('github.com/crda/test', vuln)
        self.assertIn('github.com/crda/test/package1', vuln)
        self.assertIsInstance(vuln.get('github.com/crda/test/package1', {}).get(
            'v0.0.0-20180902000632-abcd4321dcba', {}).get('cve'), list)
        self.assertEqual(len(vuln.get('github.com/crda/test/package1', {}).get(
            'v0.0.0-20180902000632-abcd4321dcba', {}).get('cve')), 1)

    def test_filter_vulnerable_packages_different_version(self):
        """Test vuln filtering for module/packages with different version."""
        vulnerabilities = self.gremlin_vulnerabilities.get('result', {}).get('data', [])
        package_version_map = {
            'github.com/crda/test': {'v0.0.0-20160902000632-abcd4321dcba': {}},
            'github.com/crda/test/package1': {
                'v0.0.0-20180902000632-abcd4321dcba': {},
                'v0.0.0-20201002000632-dcbaabcd4321': {}}
        }
        vuln = GraphAnalyses.filter_vulnerable_packages(vulnerabilities, package_version_map)
        self.assertIsInstance(vuln, dict)
        self.assertEqual(len(vuln), 2)
        self.assertIn('github.com/crda/test', vuln)
        self.assertIn('github.com/crda/test/package1', vuln)
        self.assertIsInstance(vuln.get('github.com/crda/test/package1', {}).get(
            'v0.0.0-20180902000632-abcd4321dcba', {}).get('cve'), list)
        self.assertEqual(len(vuln.get('github.com/crda/test/package1', {}).get(
            'v0.0.0-20180902000632-abcd4321dcba', {}).get('cve')), 1)
        self.assertEqual(vuln.get('github.com/crda/test/package1', {}).get(
            'v0.0.0-20181002000632-dcbaabcd4321', None), None)

    @patch('bayesian.utility.db_gateway.GraphAnalyses.get_vulnerabilities_for_packages')
    @patch('bayesian.utility.db_gateway.GraphAnalyses.get_package_details')
    def test_get_batch_ca_data_for_pseudo_version(self, _mockpckg, _mockvuln):
        """Test pseudo version gremlin query."""
        _mockpckg.return_value = self.gremlin_packages
        _mockvuln.return_value = self.gremlin_vulnerabilities

        packages = [
            {'name': 'github.com/crda/test', 'version': 'v0.0.0-20160902000632-abcd4321dcba',
             'is_pseudo_version': True},
            {'name': 'github.com/crda/test/package1',
             'version': 'v0.0.0-20180902000632-abcd4321dcba', 'is_pseudo_version': True}
        ]
        ga = GraphAnalyses.get_batch_ca_data_for_pseudo_version('eco', packages)
        self.assertIsInstance(ga, dict)
        self.assertIn('result', ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn('requestId', ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn('status', ga)
        self.assertIsInstance(ga.get('status'), dict)


class TestRdbAnalyses(unittest.TestCase):
    """Test RDB Analyses."""

    @patch('bayesian.utility.db_gateway.fetch_sa_request', return_value={})
    def test_get_request_data_success(self, _fetch_sa_request):
        """Test get SA request data."""
        rdbAnalyses = RdbAnalyses('dummy_request_id')
        self.assertEqual(rdbAnalyses.get_request_data(), {})

    @patch('bayesian.utility.db_gateway.fetch_sa_request', return_value=None)
    def test_get_request_data_error(self, _fetch_sa_request):
        """Test get SA request data with return as 404 error."""
        rdbAnalyses = RdbAnalyses('dummy_request_id')
        with pytest.raises(Exception) as exception:
            rdbAnalyses.get_request_data()
        self.assertIs(exception.type, RDBInvalidRequestException)

    @patch('bayesian.utility.db_gateway.retrieve_worker_result', return_value={})
    def test_get_stack_result(self, _fetch_sa_request):
        """Test get SA stack result."""
        rdbAnalyses = RdbAnalyses('dummy_request_id')
        self.assertEqual(rdbAnalyses.get_stack_result(), {})

    @patch('bayesian.utility.db_gateway.retrieve_worker_result', return_value={})
    def test_get_recommendation_data(self, _fetch_sa_request):
        """Test get SA recommendation data."""
        rdbAnalyses = RdbAnalyses('dummy_request_id')
        self.assertEqual(rdbAnalyses.get_recommendation_data(), {})

    @patch('bayesian.utility.db_gateway.rdb.session.execute',
           side_effect=SQLAlchemyError('Mock exception'))
    def test_save_post_request_error(self, _execute):
        """Test error save request that raises exception."""
        rdbAnalyses = RdbAnalyses('dummy_request_id', '', {}, {})
        with pytest.raises(Exception) as exception:
            rdbAnalyses.save_post_request()
        self.assertIs(exception.type, RDBSaveException)

    @patch('bayesian.utility.db_gateway.rdb.session.execute', return_value=0)
    @patch('bayesian.utility.db_gateway.rdb.session.commit', return_value=0)
    def test_save_post_request_success(self, _commit, _execute):
        """Test success save request."""
        rdbAnalyses = RdbAnalyses('dummy_request_id', '', {}, {})
        self.assertEqual(rdbAnalyses.save_post_request(), None)
