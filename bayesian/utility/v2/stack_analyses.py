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

import os
import datetime
import uuid
import json

from requests_futures.sessions import FuturesSession
from flask import current_app

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from bayesian import rdb
from bayesian.exceptions import HTTPError
from bayesian.utils import (check_for_accepted_ecosystem,
                            resolved_files_exist,
                            fetch_sa_request,
                            retrieve_worker_result)
from bayesian.dependency_finder import DependencyFinder
from f8a_worker.models import StackAnalysisRequest


worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)


class StackAnalyses():
    """Implements stack analysis API.

    Implements methods to support stack analyses post and get REST APIs calls.
    """

    def __init__(self, ecosystem=None, manifest=None, file_path=None, show_transitive=None):
        """Initialize params to be used for ."""
        self.ecosystem = ecosystem
        self.manifest = manifest
        self.file_path = file_path
        self.show_transitive = show_transitive

        # Private members used during post request.
        self._new_request_id = None
        self._request_date_str = None
        self._manifest_file_info = None

    def post_request(self):
        """Make stack analyses POST request."""
        # Make backbone request
        deps = self._make_backbone_request()

        # Finally save results in RDS and upon success return request id.
        if self._save_request(deps) == 0:
            return {
                "status": "success",
                "submitted_at": self._date_str,
                "id": self._new_request_id
            }

    def validate_params(self):
        """Validate mandatory post params of the request."""
        # Manifest is mandatory and must be a string.
        if self.manifest is None or not resolved_files_exist(self.manifest.filename):
            error_message = "Error processing request. " \
                            "Manifest is missing its value '{}' is " \
                            "invalid / not supported".format(self.manifest)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # File path is mandatory and must be a string.
        if self.file_path is None or not isinstance(self.file_path, str):
            error_message = "Error processing request. " \
                            "File path is missing / its value " \
                            "'{}' is invalid".format(self.file_path)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Ecosystem  is mandatory and must be a string.
        if self.ecosystem is None or not isinstance(self.ecosystem, str):
            error_message = "Error processing request. " \
                            "Ecosystem is missing / its value '{}' " \
                            "is invalid".format(self.ecosystem)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Below ecosystem map tries to find the map entry for given ecosystem.
        ecosystem_map = {
            "node": "npm",
            "python": "pypi",
            "java": "maven"
        }
        # If given ecosystem is not found in above map, than uses the value passed in the request.
        self.ecosystem = ecosystem_map.get(self.ecosystem, self.ecosystem)
        current_app.logger.info("Final ecosystem after mapping is '{}'".format(self.ecosystem))

        # Ecosystem should be a valid value
        if not check_for_accepted_ecosystem(self.ecosystem):
            error_message = "Error processing request. " \
                            "'{}' ecosystem is not supported".format(self.ecosystem)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

    def prepare_request(self):
        """Prepare post request by creating manifest file info and unique request id."""
        # Build manifest info from manifest file and path. It read content in utf-8 encoding.
        self._manifest_file_info = {
            "filename": self.manifest.filename,
            "filepath": self.file_path,
            "content": self.manifest.read().decode('utf-8')
        }
        current_app.logger.info(self._manifest_file_info)

        # Generate unique request id using UUID, also record timestamp in readable form
        self._new_request_id = str(uuid.uuid4().hex)
        self._date_str = str(datetime.datetime.now())

    def get_request_data(self, external_new_request_id):
        """Read request data for given request id from RDS."""
        db_result = fetch_sa_request(rdb, external_new_request_id)
        if db_result is None:
            error_message = "Invalid request ID '{}'.".format(external_new_request_id)
            current_app.logger.error(error_message)
            raise HTTPError(404, error=error_message)

        return db_result

    def get_stack_result(self, external_new_request_id):
        """Read and return stack result from RDS."""
        return retrieve_worker_result(rdb, external_new_request_id, "stack_aggregator_v2")

    def get_recommendation_data(self, external_new_request_id):
        """Read and return recommendation data from RDS."""
        return retrieve_worker_result(rdb, external_new_request_id, "recommendation_v2")

    def _read_deps_and_packages(self):
        """Read dependencies and packages information from manifest file content."""
        deps = {}
        packages = []

        # Dependency finder
        d = DependencyFinder()
        deps = d.scan_and_find_dependencies(self.ecosystem, [self._manifest_file_info],
                                            self.show_transitive)

        # Build package details.
        for p in deps['result'][0]['details'][0]['_resolved']:
            packages.append({
                'name': p['package'],
                'version': p['version'],
                'dependencies': p['deps']
            })

        return deps, packages

    def _make_backbone_request(self):
        """Perform backbone request for stack_aggregator and recommender."""
        deps = {}

        try:
            # Read backbone API end-point from application configuraton.
            backbone_host = current_app.config['F8_API_BACKBONE_HOST']
            current_app.logger.debug("Using backbone host: {}".format(backbone_host))

            # Read deps and packages from manifest
            deps, packages = self._read_deps_and_packages()
            current_app.logger.info("deps: {}".format(deps))

            # Set backbone API request body and params.
            backbone_req_body = {
                "registration_status": "freetier",
                "external_request_id": self._new_request_id,
                "ecosystem": self.ecosystem,
                "packages": packages,
                "manifest_file": self._manifest_file_info["filename"],
                "manifest_file_path": self._manifest_file_info["filepath"],
                "show_transitive": self.show_transitive
            }
            backbone_req_params = {
                "persist": "true",
                "check_license": "false"
            }
            current_app.logger.debug("Making backbone v2 request with body: {} and "
                                     "params: {}".format(backbone_req_body, backbone_req_params))

            # Post Backbone stack_aggregator call.
            _session.post(
                "{}/api/v2/stack_aggregator".format(backbone_host),
                json=backbone_req_body,
                params=backbone_req_params)

            # Post Backbone recommender call.
            _session.post(
                "{}/api/v2/recommender".format(backbone_host),
                json=backbone_req_body,
                params=backbone_req_params)

        except (ValueError, json.JSONDecodeError) as e:
            current_app.logger.exception("Invalid dependencies encountered. {}".format(e))
            raise HTTPError(400, "Invalid dependencies encountered. {}".format(e))
        except Exception as exc:
            current_app.logger.exception("Could not process {}, exception {}".format(
                self._new_request_id, exc))
            raise HTTPError(500, ("Could not process {}".format(self._new_request_id))) from exc

        return deps

    def _save_request(self, deps):
        """Save the post request data into RDS."""
        try:
            insert_stmt = insert(StackAnalysisRequest).values(
                id=self._new_request_id,
                submitTime=self._date_str,
                requestJson={'manifest': self._manifest_file_info},
                dep_snapshot=deps
            )
            do_update_stmt = insert_stmt.on_conflict_do_update(
                index_elements=['id'],
                set_=dict(dep_snapshot=deps)
            )
            rdb.session.execute(do_update_stmt)
            rdb.session.commit()

            return 0
        except SQLAlchemyError as e:
            current_app.logger.exception("Error updating log for request {}, exception {}".format(
                self._new_request_id, e))
            raise HTTPError(500, "Error updating log for request {}".format(
                self._new_request_id)) from e
