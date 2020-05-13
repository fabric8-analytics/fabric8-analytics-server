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
"""Test stack analyses class."""

import unittest
from pathlib import Path
from unittest.mock import patch
from bayesian.utility.v2.stack_analyses import StackAnalyses


class TestStackAnalyses(unittest.TestCase):
    """Stack Analyses Unit Tests."""

    @classmethod
    def setUpClass(cls):
        """Fill in manifest file info required by all test cases."""
        cls.manifest_file_info = {
            'filename': 'npmlist.json',
            'filepath': '/tmp/bin',
            'content': open(str(Path(__file__).parent.parent.parent) +
                            '/data/manifests/202/npmlist.json').read()
        }

    def test_sa_invalid_manifest_file(self):
        """Check if 400 is raise upon invalid manifest file."""
        manifest_file_info = {
            'filename': 'npmlist.json',
            'filepath': '/tmp/bin',
            'content': open(str(Path(__file__).parent.parent.parent) +
                            '/data/manifests/400/npmlist.json').read()
        }
        sa = StackAnalyses(None, 'npm', manifest_file_info, True)
        status, data = sa.post_request()
        assert status == 400

    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_aggregate_request',
           return_value=-1)
    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_recommendations_request',
           return_value=-1)
    def test_sa_backbone_error(self, _recommendations_request, _aggregate_request):
        """Check if 500 is raise upon invalid response from backbone server."""
        sa = StackAnalyses(None, 'npm', self.manifest_file_info, True)
        status, data = sa.post_request()
        assert status == 500

    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_aggregate_request',
           return_value=0)
    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_recommendations_request',
           return_value=0)
    @patch('bayesian.utility.v2.stack_analyses.RdbAnalyses.save_post_request', return_value=-1)
    def test_sa_rdb_error(self, _post_request, _recommendations_request, _aggregate_request):
        """Check if 500 is raise upon request save failure."""
        sa = StackAnalyses(None, 'npm', self.manifest_file_info, True)
        status, data = sa.post_request()
        assert status == 500

    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_aggregate_request',
           return_value=0)
    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_recommendations_request',
           return_value=0)
    @patch('bayesian.utility.v2.stack_analyses.RdbAnalyses.save_post_request', return_value=0)
    def test_sa_success(self, _post_request, _recommendations_request, _aggregate_request):
        """Success stack analyses flow."""
        sa = StackAnalyses(None, 'npm', self.manifest_file_info, True)
        status, data = sa.post_request()
        assert status == 200
