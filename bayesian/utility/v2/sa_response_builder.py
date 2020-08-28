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
"""Stack analyses API v2 response builder class."""

import logging
from flask import g
from bayesian.utils import request_timed_out
from bayesian.utility.user_utils import UserStatus

logger = logging.getLogger(__name__)


class StackAnalysesResponseBuilder:
    """Stack analysis response builder for API v2.

    Class takes db result, stack result and recommendation data to verify and build stack
    analyses response for V1.
    """

    def __init__(self, external_request_id, uuid, rdb_analyses):
        """Response Builder, Build Json Response for Stack Analyses."""
        self.external_request_id = external_request_id
        self.uuid = uuid
        self.rdb_analyses = rdb_analyses

    def get_response(self):
        """Aggregate, build and return json response for the given request id."""
        logger.info('%s SA Get request', self.external_request_id)

        # Get db result, stack result and recm data from rdb.
        self._db_result = self.rdb_analyses.get_request_data()
        self._stack_result = self.rdb_analyses.get_stack_result()
        self._recm_data = self.rdb_analyses.get_recommendation_data()

        # If request is invalid, it will raise exception with proper message.
        self._raise_if_invalid()

        # If request is inprogress or timeout, it will raise exception with proper message.
        self._raise_if_inprogress_or_timeout()

        # Proceed with building actual response from data.
        stack_task_result = self._stack_result.get('task_result')
        stack_audit = stack_task_result.get('_audit', {})

        report = {
            'version': stack_audit.get('version', None),
            'started_at': stack_audit.get('started_at', None),
            'ended_at': stack_audit.get('ended_at', None),
            'external_request_id': self.external_request_id,
            'uuid': self.uuid,
            'registration_status': stack_task_result.get('registration_status', ''),
            'manifest_file_path': stack_task_result.get('manifest_file_path', ''),
            'manifest_name': stack_task_result.get('manifest_name', ''),
            'ecosystem': stack_task_result.get('ecosystem', ''),
            'unknown_dependencies': stack_task_result.get('unknown_dependencies', ''),
            'license_analysis': stack_task_result.get('license_analysis', ''),
            'recommendation': self._recm_data.get('task_result', {}),
            'analyzed_dependencies': self._get_analysed_dependencies(
                stack_task_result.get('analyzed_dependencies', []))
        }

        if g.user_status == UserStatus.FREETIER:
            report['registration_link'] = stack_task_result.get('registration_link', ''),

        return report

    def _raise_if_invalid(self):
        """If request is invalid than it shall raise an exception."""
        if self._stack_result == -1 and self._recm_data == -1:
            error_message = 'Worker result for request ID {} does not exist yet'.format(
                            self.external_request_id)
            logger.exception(error_message)
            raise SARBRequestInvalidException(error_message)

    def _raise_if_inprogress_or_timeout(self):
        """Check if request is in progress."""
        if self._stack_result is None or self._recm_data is None:
            # If the response is not ready and the timeout period is over, send error 408
            if request_timed_out(self._db_result):
                error_message = 'Stack analysis request {} has timed out. Please retry ' \
                                'with a new analysis.'.format(self.external_request_id)
                logger.error(error_message)
                raise SARBRequestTimeoutException(error_message)
            else:
                error_message = 'Analysis for request ID {} is in progress'.format(
                    self.external_request_id)
                logger.warning(error_message)
                raise SARBRequestInprogressException(error_message)

    def _get_analysed_dependencies(self, analysed_dependencies):
        """Filter report fields based on user status."""
        if g.user_status != UserStatus.REGISTERED:
            freetier_user_fields = ['cve_ids', 'cvss', 'cwes',
                                    'cvss_v3', 'severity', 'title', 'id', 'url']
            for dependency in analysed_dependencies:
                self._filter_fields(freetier_user_fields, dependency)

        return analysed_dependencies

    def _filter_fields(self, required_fields, dependency):
        """Keep only freetier fields for given dependency."""
        for index, public_vul in enumerate(dependency.get('public_vulnerabilities', [])):
            for key in list(public_vul.keys()):
                if key not in required_fields:
                    del dependency['public_vulnerabilities'][index][key]
        for index, private_vul in enumerate(dependency.get('private_vulnerabilities', [])):
            for key in list(private_vul.keys()):
                if key not in required_fields:
                    del dependency['private_vulnerabilities'][index][key]
        for vulnerable_dependency in dependency.get('vulnerable_dependencies', []):
            self._filter_fields(required_fields, vulnerable_dependency)


class SARBRequestInvalidException(Exception):
    """Exception raised when both stack result and recommendation data is empty in RDB.

    Indicate RDB could not get either result data / recommendation data for a given request id.
    """

    pass


class SARBRequestInprogressException(Exception):
    """Exception raised when request is in progress.

    Indicate stack analyses backbone service is still processing the given request id.
    """

    pass


class SARBRequestTimeoutException(Exception):
    """Exception raised when request timeout.

    Indicate given request id was timed out while generating stack analyses data.
    """

    pass
