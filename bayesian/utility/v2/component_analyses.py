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
"""Component Analyses Utility Stand."""

import logging
import os
import re
import time
from collections import namedtuple
from typing import Dict, Set, List, Tuple
from flask import g
from bayesian.utility.v2.ca_response_builder import CABatchResponseBuilder
from bayesian.utils import check_for_accepted_ecosystem, \
    server_create_analysis, server_create_component_bookkeeping
from f8a_worker.utils import MavenCoordinates
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)
Package = namedtuple("Package", ["name", "version", "package_unknown"])


def validate_version(version: str) -> bool:
    """Version should not contain special Characters."""
    logger.debug('Version validator.')
    if re.findall('[!@#$%^&*()]', version):
        return False
    return True


def normlize_packages(package, version) -> Package:
    """Normalise Packages into hashable."""
    logger.debug('Normalizing Packages.')
    return Package(name=package, version=version, package_unknown=True)


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple]) -> bool:
    """Unknown Package flow. Trigger bayesianApiFlow."""
    logger.debug('Triggered Unknown Package Flow.')
    api_flow: bool = os.environ.get("INVOKE_API_WORKERS", "") == "1"
    started_at = time.time()
    for pkg in unknown_pkgs:
        server_create_analysis(ecosystem, pkg.name, pkg.version, user_profile=g.decoded_token,
                               api_flow=api_flow, force=False, force_graph_sync=True)
    elapsed_time = time.time() - started_at
    logger.info('Unknown flow for %f packages took %f seconds', len(unknown_pkgs), elapsed_time)
    return True


def known_package_flow(ecosystem: str, package: str, version: str) -> bool:
    """Known Package flow.Trigger componentApiFlow."""
    logger.debug('Triggered Known Package Flow.')
    server_create_component_bookkeeping(
        ecosystem, package, version, g.decoded_token)
    return True


def ca_validate_input(input_json: Dict, ecosystem: str) -> Tuple[List[Dict], List[Package]]:
    """Validate CA Input."""
    logger.debug('Validating ca input data.')
    if not input_json:
        error_msg = "Expected JSON request"
        raise BadRequest(error_msg)

    if not isinstance(input_json, dict):
        error_msg = "Expected list of dependencies in JSON request"
        raise BadRequest(error_msg)

    if not check_for_accepted_ecosystem(ecosystem):
        error_msg: str = f"Ecosystem {ecosystem} is not supported for this request"
        raise BadRequest(error_msg)

    if not input_json.get('package_versions'):
        error_msg: str = "package_versions is missing"
        raise BadRequest(error_msg)

    packages_list = []
    normalised_input_pkgs = []
    for pkg in input_json.get('package_versions'):
        package = pkg.get("package")
        version = pkg.get("version")
        if not all([package, version]):
            error_msg = "Invalid Input: Package, Version are required."
            raise BadRequest(error_msg)

        if (not isinstance(version, str)) or (not isinstance(package, str)):
            error_msg = "Package version should be string format only."
            raise BadRequest(error_msg)

        if not validate_version(version):
            error_msg = "Package version should not have special characters."
            raise BadRequest(error_msg)

        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)

        if ecosystem == 'pypi':
            package = package.lower()
        packages_list.append({"name": package, "version": version})
        normalised_input_pkgs.append(normlize_packages(package, version))
    return packages_list, normalised_input_pkgs


def get_known_unknown_pkgs(
        ecosystem: str, graph_response: Dict,
        normalised_input_pkgs: List) -> Tuple[List[Dict], Set[Package]]:
    """Analyse Known and Unknown Packages."""
    stack_recommendation = []
    db_known_packages = set()
    for package in graph_response.get('result', {}).get('data'):
        pkg_name = package.get('package').get('name', [''])[0]
        pkg_vr = package.get('version').get('version', [''])[0]
        pkg_recomendation = CABatchResponseBuilder(ecosystem).generate_recommendation(package)
        stack_recommendation.append(pkg_recomendation)
        known_package_flow(ecosystem, pkg_recomendation["package"], pkg_recomendation["version"])
        db_known_packages.add(normlize_packages(pkg_name, pkg_vr))

    input_dependencies = set(normalised_input_pkgs)
    unknown_pkgs: Set = input_dependencies.difference(db_known_packages)
    return stack_recommendation, unknown_pkgs


def build_pkg_recommendation(pack_details, ecosystem) -> Dict:
    """Build Package Recommendation."""
    logger.debug('Building Package Recommendation.')
    pkg_recomendation = CABatchResponseBuilder(ecosystem).generate_recommendation(pack_details)
    known_package_flow(
        ecosystem, pkg_recomendation["package"], pkg_recomendation["version"])
    return pkg_recomendation


def add_unknown_pkg_info(stack_recommendation: List, unknown_pkgs: Set[Package]) -> List:
    """Add Unknown Package Info in stack_recommendation.

    :param stack_recommendation:
    :param unknown_pkgs:
    :return: Updated Stack Recommendation
    """
    for unknown_pkg in unknown_pkgs:
        stack_recommendation.append(
            unknown_pkg._asdict())
    return stack_recommendation
