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


class StackAnalysesResponseBuilder:
    """Stack analysis response builder for API v2."""

    def __init__(self, external_request_id, stack_result, recm_data):
        """Response Builder, Build Json Response for Stack Analyses."""
        self.external_request_id = external_request_id
        self.stack_result = stack_result
        self.recm_data = recm_data

    def get_response(self):
        """Aggregate, build and return json response for the given request id."""
        stack_task_result = None
        stack_audit = None
        recommendations = []

        if self.stack_result is not None and "task_result" in self.stack_result:
            stack_task_result = self.stack_result.get("task_result", None)
            stack_audit = stack_task_result.get("_audit", {})

        if self.recm_data is not None and "task_result" in self.recm_data:
            recommendations = self.recm_data.get("task_result", {}).get("recommendations", [])[0]

        response_data = {}
        if stack_task_result is not None:
            response_data = {
                "version": stack_audit.get("version", None),
                "started_at": stack_audit.get("started_at", None),
                "ended_at": stack_audit.get("ended_at", None),
                "external_request_id": self.external_request_id,
                "registration_status": stack_task_result.get("registration_status", ""),
                "manifest_file_path": stack_task_result.get("manifest_file_path", ""),
                "manifest_name": stack_task_result.get("manifest_name", ""),
                "ecosystem": stack_task_result.get("ecosystem", ""),
                "unknown_dependencies": stack_task_result.get("unknown_dependencies", ""),
                "license_analysis": stack_task_result.get("license_analysis", ""),
                "recommendation": {
                    "companion": recommendations.get("companion", []),
                    "manifest_file_path": recommendations.get("manifest_file_path", ""),
                    "usage_outliers": recommendations.get("usage_outliers", [])
                },
                "registration_link": stack_task_result.get("registration_link", ""),
                "analyzed_dependencies": stack_task_result.get("analyzed_dependencies", [])
            }
        else:
            response_data = {
                "error": "Enable to fetch the result for request id '{}'".format(
                    self.external_request_id)
            }

        return response_data
