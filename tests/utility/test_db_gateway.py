"""Test DB Communicator."""

import unittest
from bayesian.utility.db_gateway import GraphAnalyses
from unittest.mock import patch
import os
import json


class DbgatewayTest(unittest.TestCase):
    """Test Communicator."""

    @classmethod
    def setUpClass(cls):
        """Class variables initialised."""
        cls.eco = 'eco'
        cls.ver = '1'
        cls.pkg = 'pkg'

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
        self.assertIn("result", ga)
        self.assertIsInstance(ga.get('result'), dict)
        self.assertIn("requestId", ga)
        self.assertIsInstance(ga.get('requestId'), str)
        self.assertIn("status", ga)
        self.assertIsInstance(ga.get('status'), dict)
