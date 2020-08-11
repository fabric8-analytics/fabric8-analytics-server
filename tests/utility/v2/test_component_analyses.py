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

import unittest
from unittest.mock import patch
from bayesian.utility.v2.component_analyses import validate_version, known_package_flow


class TestComponentAnalyses(unittest.TestCase):
    """Test Component Analyses Utility class."""

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
