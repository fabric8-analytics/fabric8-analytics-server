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
"""Test stack analyses response builder class."""

import json
import pytest
import unittest
from pathlib import Path
from unittest.mock import patch
from bayesian.utility.user_utils import UserStatus
from bayesian.utility.v2.sa_response_builder import (StackAnalysesResponseBuilder,
                                                     SARBRequestInvalidException,
                                                     SARBRequestInprogressException,
                                                     SARBRequestTimeoutException)
from bayesian.utility.v2.sa_models import (StackAggregatorResultForFreeTierUser,
                                           StackAggregatorResultForRegisteredUser)


class TestStackAnalysesResponseBuilder(unittest.TestCase):
    """Stack Analyses Response Builder Unit Tests."""

    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=False)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_worker_error(self, _rdb_analyses, _timed_out):
        """Test SA response builder with invalid values for stack result and recm data."""
        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = -1
        _rdb_analyses.get_recommendation_data.return_value = -1
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        # Expect SARBRequestInvalidException error.
        with pytest.raises(Exception) as exception:
            assert sa_response_builder.get_response()
        self.assertIs(exception.type, SARBRequestInvalidException)

    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=False)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_inprogress(self, _rdb_analyses, _timed_out):
        """Test SA response builder with None data."""
        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = None
        _rdb_analyses.get_recommendation_data.return_value = None
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        # Raises SARBRequestInprogressException error for request in progress
        with pytest.raises(Exception) as exception:
            assert sa_response_builder.get_response()
        self.assertIs(exception.type, SARBRequestInprogressException)

    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=True)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_timeout(self, _rdb_analyses, _timed_out):
        """Test SA response builder with missing recm data."""
        stack_result = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_stack_result.json') as f:
            stack_result = json.load(f)

        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = stack_result
        _rdb_analyses.get_recommendation_data.return_value = None
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        # Raises SARBRequestTimeoutException error
        with pytest.raises(Exception) as exception:
            assert sa_response_builder.get_response()
        self.assertIs(exception.type, SARBRequestTimeoutException)

    @patch('bayesian.utility.v2.sa_response_builder.g')
    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=False)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_freetier_success(self, _rdb_analyses, _timed_out, _g):
        """Test SA response builder with all proper data."""
        stack_result = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_stack_result.json') as f:
            stack_result = json.load(f)
            stack_result['task_result']['registration_status'] = UserStatus.FREETIER.name
            stack_result['task_result']['uuid'] = '97b3c23e-d3da-4336-8b82-2abdac2075e1'

        recm_data = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_recm_data.json') as f:
            recm_data = json.load(f)

        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = stack_result
        _rdb_analyses.get_recommendation_data.return_value = recm_data
        _g.user_status = UserStatus.FREETIER
        _g.uuid = '97b3c23e-d3da-4336-8b82-2abdac2075e2'
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        response = sa_response_builder.get_response()
        self.assertEqual(response['uuid'], '97b3c23e-d3da-4336-8b82-2abdac2075e2')
        self.assertEqual(response['registration_status'], UserStatus.FREETIER.name)

        sa = StackAggregatorResultForFreeTierUser(**response)
        self.assertNotEqual(sa, None)

    @patch('bayesian.utility.v2.sa_response_builder.g')
    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=False)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_registration_success(self, _rdb_analyses, _timed_out, _g):
        """Test SA response builder with all proper data."""
        stack_result = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_stack_result.json') as f:
            stack_result = json.load(f)
            stack_result['task_result']['registration_status'] = UserStatus.REGISTERED.name
            stack_result['task_result']['uuid'] = None

        recm_data = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_recm_data.json') as f:
            recm_data = json.load(f)

        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = stack_result
        _rdb_analyses.get_recommendation_data.return_value = recm_data
        _g.user_status = UserStatus.REGISTERED
        _g.uuid = '97b3c23e-d3da-4336-8b82-2abdac2075e1'
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        response = sa_response_builder.get_response()
        self.assertEqual(response['uuid'], '97b3c23e-d3da-4336-8b82-2abdac2075e1')
        self.assertEqual(response['registration_status'], UserStatus.REGISTERED.name)

        sa = StackAggregatorResultForRegisteredUser(**response)
        self.assertNotEqual(sa, None)

    @patch('bayesian.utility.v2.sa_response_builder.g')
    @patch('bayesian.utility.v2.sa_response_builder.request_timed_out', return_value=False)
    @patch('bayesian.utility.db_gateway.RdbAnalyses')
    def test_sa_response_builder_expired_success(self, _rdb_analyses, _timed_out, _g):
        """Test SA response builder with all proper data."""
        stack_result = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_stack_result.json') as f:
            stack_result = json.load(f)
            stack_result['task_result']['registration_status'] = UserStatus.EXPIRED.name
            stack_result['task_result']['uuid'] = None

        recm_data = None
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/backbone/v2_recm_data.json') as f:
            recm_data = json.load(f)

        _rdb_analyses.get_request_data.return_value = None
        _rdb_analyses.get_stack_result.return_value = stack_result
        _rdb_analyses.get_recommendation_data.return_value = recm_data
        _g.user_status = UserStatus.EXPIRED
        _g.uuid = None
        sa_response_builder = StackAnalysesResponseBuilder('DUMMY_REQUEST_ID',
                                                           _rdb_analyses)
        response = sa_response_builder.get_response()
        self.assertEqual(response['uuid'], None)
        self.assertEqual(response['registration_status'], UserStatus.EXPIRED.name)

        sa = StackAggregatorResultForFreeTierUser(**response)
        self.assertNotEqual(sa, None)
