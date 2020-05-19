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
"""Stack analyses API v2 class, implementing functionality to server POST and GET requests."""

import datetime
import uuid
import json
import logging
from bayesian.dependency_finder import DependencyFinder
from bayesian.exceptions import HTTPError
from bayesian.utility.db_gateway import RdbAnalyses
from bayesian.utility.v2.backbone_server import BackboneServer

logger = logging.getLogger(__file__)


class StackAnalyses():
    """Implements stack analysis API.

    Implements methods to support stack analyses post and get REST APIs calls.
    """

    def __init__(self, external_request_id=None, params=None):
        """Initialize params to be used for ."""
        self.external_request_id = external_request_id
        self.params = params

    def post_request(self):
        """Make stack analyses POST request."""
        logger.debug('SA Post request with ecosys: {} fl name: {} path: {} '
                     'st: {}'.format(self.params.ecosystem, self.params.manifest.filename,
                                     self.params.file_path, self.params.show_transitive))
        # Build manifest file info.
        self._manifest_file_info = {
            'filename': self.params.manifest.filename,
            'filepath': self.params.file_path,
            'content': self.params.manifest.read().decode('utf-8')
        }
        logger.info('manifest_file_info: {}'.format(self._manifest_file_info))

        # Generate unique request id using UUID, also record timestamp in readable form
        self.external_request_id = str(uuid.uuid4().hex)
        date_str = str(datetime.datetime.now())

        # Make backbone request
        deps = self._make_backbone_request()

        # Finally save results in RDS and upon success return request id.
        rdbAnalyses = RdbAnalyses(self.external_request_id, date_str,
                                  self._manifest_file_info, deps)
        rdbAnalyses.save_post_request()
        return {
            'status': 'success',
            'submitted_at': date_str,
            'id': self.external_request_id
        }

    def _read_deps_and_packages(self):
        """Read dependencies and packages information from manifest file content."""
        deps = {}
        packages = []

        try:
            # Dependency finder
            d = DependencyFinder()
            deps = d.scan_and_find_dependencies(self.params.ecosystem, [self._manifest_file_info],
                                                self.params.show_transitive)

            # Build package details.
            resolved = deps.get('result', [{}])[0].get('details', [{}])[0].get('_resolved', None)
            if resolved is not None:
                for p in resolved:
                    packages.append({
                        'name': p.get('package', ''),
                        'version': p.get('version', ''),
                        'dependencies': [{'name': pkg['package'], 'version': pkg['version']}
                                         for pkg in p.get('deps', [])]
                    })

            return {'deps': deps, 'packages': packages}
        except (ValueError, json.JSONDecodeError) as e:
            logger.exception('Invalid dependencies encountered. {}'.format(e))
            raise HTTPError(400, 'Error while parsing dependencies information')

    def _make_backbone_request(self):
        """Perform backbone request for stack_aggregator and recommender."""
        # Read deps and packages from manifest
        data = self._read_deps_and_packages()
        logger.info('deps data: {}'.format(data))

        # Set backbone API request body and params.
        request_body = {
            'registration_status': 'freetier',
            'external_request_id': self.external_request_id,
            'ecosystem': self.params.ecosystem,
            'packages': data['packages'],
            'manifest_file': self._manifest_file_info['filename'],
            'manifest_file_path': self._manifest_file_info['filepath'],
            'show_transitive': self.params.show_transitive
        }
        request_params = {
            'persist': 'true',
            'check_license': 'false'
        }
        # Post Backbone stack_aggregator call.
        BackboneServer.post_aggregate_request(request_body, request_params)
        BackboneServer.post_recommendations_request(request_body, request_params)

        return data['deps']
