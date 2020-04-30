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
"""Implements /api/v2/stack-analyses REST APIs for POST and GET."""

import os
import datetime
import uuid
import json

from requests_futures.sessions import FuturesSession
from flask import current_app, request
from flask_restful import Resource

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from bayesian import rdb
from bayesian.exceptions import HTTPError
from bayesian.utils import (check_for_accepted_ecosystem,
                            resolved_files_exist,
                            fetch_sa_request,
                            retrieve_worker_result,
                            request_timed_out)
from bayesian.dependency_finder import DependencyFinder

from fabric8a_auth.auth import login_required

from f8a_worker.models import StackAnalysisRequest


worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)


class StackAnalyses(Resource):
    """Implements stack analysis REST APIs.

    Implements /api/v2/stack-analyses REST APIs for POST and GET calls.
    """

    method_decorators = [login_required]

    @staticmethod
    def get(external_request_id):
        """Handle /api/v2/stack-analyses GET REST API."""
        current_app.logger.info("GET request_id: {}".format(external_request_id))

        # 1. Read request from RDS
        db_result = StackAnalyses._read_request_data(rdb, external_request_id)

        # 2. Read stack results from RDS
        stack_result = StackAnalyses._read_stack_result(rdb, external_request_id)

        # 3. Read recommendation data from RDS
        recm_data = StackAnalyses._read_recommendation_data(rdb, external_request_id)

        # 4. If stack or reco is missing, either we are in progress or we have timedout.
        if stack_result is None or recm_data is None:
            # If the response is not ready and the timeout period is over, send error 408
            if request_timed_out(db_result):
                error_message = "Stack analysis request {} has timed out. Please retry " \
                                "with a new analysis.".format(external_request_id)
                current_app.logger.error(error_message)
                raise HTTPError(408, error=error_message)
            else:
                error_message = "Analysis for request ID '{}' is in progress".format(
                    external_request_id)
                current_app.logger.error(error_message)
                return {'error': error_message}, 202

        # 5. Some rare case when workers have not updated the result
        if stack_result == -1 and recm_data == -1:
            error_message = "Worker result for request ID '{}' doesn't exist yet".format(
                external_request_id)
            current_app.logger.error(error_message)
            raise HTTPError(404, error=error_message)

        # 6. Assmble final response and return
        return StackAnalyses._build_get_response(external_request_id, stack_result, recm_data)

    @staticmethod
    def _read_request_data(rdb, external_request_id):
        """Read request data for given request id from RDS."""
        db_result = fetch_sa_request(rdb, external_request_id)
        if db_result is None:
            error_message = "Invalid request ID '{}'.".format(external_request_id)
            current_app.logger.error(error_message)
            raise HTTPError(404, error=error_message)

        return db_result

    @staticmethod
    def _read_stack_result(rdb, external_request_id):
        """Read and return stack result from RDS."""
        return retrieve_worker_result(rdb, external_request_id, "stack_aggregator_v2")

    @staticmethod
    def _read_recommendation_data(rdb, external_request_id):
        """Read and return recommendation data from RDS."""
        return retrieve_worker_result(rdb, external_request_id, "recommendation_v2")

    @staticmethod
    def _build_get_response(external_request_id, stack_result, recm_data):
        """Aggregate, build and return json response for the given request id."""
        stack_task_result = None
        stack_audit = None
        reco_recommendations = []

        if stack_result is not None and "task_result" in stack_result:
            stack_task_result = stack_result.get("task_result", None)
            stack_audit = stack_task_result.get("_audit", {})

        if recm_data is not None and "task_result" in recm_data:
            reco_recommendations = recm_data.get("task_result", {}).get("recommendations", [])[0]

        response_data = {}
        if stack_task_result is not None:
            response_data = {
                "version": stack_audit.get("version", None),
                "started_at": stack_audit.get("started_at", None),
                "ended_at": stack_audit.get("ended_at", None),
                "external_request_id": external_request_id,
                "registration_status": stack_task_result.get("registration_status", ""),
                "manifest_file_path": stack_task_result.get("manifest_file_path", ""),
                "manifest_name": stack_task_result.get("manifest_name", ""),
                "ecosystem": stack_task_result.get("ecosystem", ""),
                "unknown_dependencies": stack_task_result.get("unknown_dependencies", ""),
                "license_analysis": stack_task_result.get("license_analysis", ""),
                "recommendation": {
                    "companion": reco_recommendations.get("companion", []),
                    "manifest_file_path": reco_recommendations.get("manifest_file_path", ""),
                    "usage_outliers": reco_recommendations.get("usage_outliers", [])
                },
                "registration_link": stack_task_result.get("registration_link", ""),
                "analyzed_dependencies": stack_task_result.get("analyzed_dependencies", [])
            }
        else:
            response_data = {
                "error": "Enable to fetch the result for request id '{}'".format(
                    external_request_id)
            }

        return response_data

    @staticmethod
    def post():
        """Handle /api/v2/stack-analyses POST REST API."""
        # 1. Read mandatory params
        manifest = request.files.get("manifest") or None
        file_path = request.form.get("file_path") or None
        ecosystem = request.form.get("ecosystem") or None

        current_app.logger.info("Mandatory params :: manifest: {} file_path: {} "
                                "ecosystem: {}".format(manifest, file_path, ecosystem))

        # 2. Read optional params and set default value as per V2 spec.
        show_transitive = request.form.get("show_transitive") or "true"

        current_app.logger.info("Optional params :: show_transitive: {}".format(show_transitive))

        # 3. Map ecosystem string using static map.
        ecosystem = StackAnalyses._map_ecosystem(ecosystem)

        current_app.logger.info("Final ecosystem is '{}' after mapping.".format(ecosystem))

        # 4. Validate all post params as per v2 spec.
        StackAnalyses._validate_post_params(manifest, file_path, ecosystem)

        # 5. Build manifest info from manifest file and path. It read content in utf-8 encoding.
        manifest_file_info = StackAnalyses._build_manifest_info(manifest, file_path)

        current_app.logger.info(manifest_file_info)

        # 6. Generate unique request id using UUID, also record timestamp in readable form
        request_id = str(uuid.uuid4().hex)
        date_str = str(datetime.datetime.now())

        # 7. Make backbone request
        deps = StackAnalyses._make_backbone_request(request_id, ecosystem, manifest_file_info,
                                                    show_transitive)

        # 8. Finally save results in RDS and upon success return request id.
        if StackAnalyses._save_request_in_rds(request_id, manifest_file_info, deps, date_str) == 0:
            return {
                "status": "success",
                "submitted_at": date_str,
                "id": request_id
            }

    @staticmethod
    def _map_ecosystem(ecosystem):
        """Map the ecosystem string to supported / well-known form."""
        # Below ecosystem map tries to find the map entry.
        ecosystem_map = {
            "node": "npm",
            "python": "pypi",
            "java": "maven"
        }
        # If given ecosystem is not found in above map, than uses the value
        # passed in the request.
        return ecosystem_map.get(ecosystem, ecosystem)

    @staticmethod
    def _validate_post_params(manifest, file_path, ecosystem):
        """Validate mandatory post params of the request."""
        # Manifest is mandatory and must be a string.
        if manifest is None or not resolved_files_exist(manifest.filename):
            error_message = "Error processing request. " \
                            "Manifest is missing its value '{}' is invalid / " \
                            "not supported".format(manifest)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # File path is mandatory and must be a string.
        if file_path is None or not isinstance(file_path, str):
            error_message = "Error processing request. " \
                            "File path is missing / its value '{}' is invalid".format(file_path)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Ecosystem  is mandatory and must be a string.
        if ecosystem is None or not isinstance(ecosystem, str):
            error_message = "Error processing request. " \
                            "Ecosystem is missing / its value '{}' is invalid".format(ecosystem)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

        # Ecosystem should be a valid value
        if not check_for_accepted_ecosystem(ecosystem):
            error_message = "Error processing request. " \
                            "'{}' ecosystem is not supported".format(ecosystem)
            current_app.logger.error(error_message)
            raise HTTPError(400, error=error_message)

    @staticmethod
    def _build_manifest_info(manifest, file_path):
        """Build and return manifest info object, it read menifest file content in utf-8 formate."""
        # Read manifest file information.
        return {
            "filename": manifest.filename,
            "filepath": file_path,
            "content": manifest.read().decode('utf-8')
        }

    @staticmethod
    def _read_deps_and_packages(ecosystem, manifest_file_info, show_transitive):
        """Read dependencies and packages information from manifest file content."""
        deps = {}
        packages = []

        # Dependency finder
        d = DependencyFinder()
        deps = d.scan_and_find_dependencies(ecosystem, [manifest_file_info], show_transitive)

        # Build package details.
        for p in deps['result'][0]['details'][0]['_resolved']:
            packages.append({
                'name': p['package'],
                'version': p['version'],
                'dependencies': p['deps']
            })

        return deps, packages

    @staticmethod
    def _build_backbone_req_body(request_id, ecosystem, packages, manifest_file_info,
                                 show_transitive):
        """Build and return backbone body object. This will be used to fire backbone requests."""
        # Set backbone API request body and params.
        return {
            "registration_status": "freetier",
            "external_request_id": request_id,
            "ecosystem": ecosystem,
            "packages": packages,
            "manifest_file": manifest_file_info["filename"],
            "manifest_file_path": manifest_file_info["filepath"],
            "show_transitive": show_transitive
        }

    @staticmethod
    def _build_backbone_req_params():
        """Build and return backbone param object. This will be used to fire backbone requests."""
        return {
            "persist": "true",
            "check_license": "false"
        }

    @staticmethod
    def _make_backbone_request(request_id, ecosystem, manifest_file_info, show_transitive):
        """Perform backbone request for stack_aggregator and recommender."""
        deps = {}

        try:
            # Read backbone API end-point from application configuraton.
            backbone_host = current_app.config['F8_API_BACKBONE_HOST']
            current_app.logger.info("Using backbone host: {}".format(backbone_host))

            # Read deps and packages from manifest
            deps, packages = StackAnalyses._read_deps_and_packages(ecosystem, manifest_file_info,
                                                                   show_transitive)
            current_app.logger.info("deps: {}".format(deps))

            # Set backbone API request body and params.
            backbone_req_body = StackAnalyses._build_backbone_req_body(request_id, ecosystem,
                                                                       packages, manifest_file_info,
                                                                       show_transitive)

            backbone_req_params = StackAnalyses._build_backbone_req_params()
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
                request_id, exc))
            raise HTTPError(500, ("Could not process {}".format(request_id))) from exc

        return deps

    @staticmethod
    def _save_request_in_rds(request_id, manifest_file_info, deps, date_str):
        """Save the post request data into RDS."""
        try:
            insert_stmt = insert(StackAnalysisRequest).values(
                id=request_id,
                submitTime=date_str,
                requestJson={'manifest': manifest_file_info},
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
                request_id, e))
            raise HTTPError(500, "Error updating log for request {}".format(request_id)) from e
