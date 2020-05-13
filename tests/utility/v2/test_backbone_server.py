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
"""Test backbone server interface class."""

import unittest
from unittest.mock import patch
from bayesian.utility.v2.backbone_server import BackboneServer


class TestBackboneServer(unittest.TestCase):
    """Test backbone server interface class."""

    @patch('bayesian.utility.v2.backbone_server.BackboneServer.session.post',
           side_effect=Exception('Mock exception'))
    def test_agg_request_error(self, _post):
        """Test aggregate post request with empty data."""
        assert BackboneServer.post_aggregate_request({}, {}) == -1

    @patch('bayesian.utility.v2.backbone_server.BackboneServer.session.post',
           return_value={})
    def test_agg_request_success(self, _post):
        """Test aggregate post request with correct data."""
        assert BackboneServer.post_aggregate_request({}, {}) == 0

    @patch('bayesian.utility.v2.backbone_server.BackboneServer.session.post',
           side_effect=Exception('Mock exception'))
    def test_recm_request_error(self, _post):
        """Test recommendation post request with empty data."""
        assert BackboneServer.post_recommendations_request({}, {}) == -1

    @patch('bayesian.utility.v2.backbone_server.BackboneServer.session.post',
           return_value={})
    def test_recm_request_success(self, _post):
        """Test recommendation post request with correct data."""
        assert BackboneServer.post_recommendations_request({}, {}) == 0
