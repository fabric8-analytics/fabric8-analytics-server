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
from collections import namedtuple
from typing import Dict, Set, List, Tuple
from flask import g
from bayesian.utility.db_gateway import GraphAnalyses
from bayesian.utils import check_for_accepted_ecosystem, \
    server_create_analysis, server_create_component_bookkeeping
from f8a_worker.utils import MavenCoordinates, case_sensitivity_transform
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)
Package = namedtuple("Package", ["name", "version"])


def validate_version(version: str) -> bool:
    """Version should not contain special Characters."""
    if re.findall('[!@#$%^&*()]', version):
        return False
    return True


def normlize_packages(packages: List[Dict]) -> List[Package]:
    """Normalise Packages into hashable."""
    return [Package(p['name'], p['version']) for p in packages]


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple]) -> bool:
    """Unknown Package flow. Trigger bayesianApiFlow."""
    api_flow: bool = os.environ.get("INVOKE_API_WORKERS", "") == "1"
    for pkg in unknown_pkgs:
        server_create_analysis(ecosystem, pkg.name, pkg.version, user_profile=g.decoded_token,
                               api_flow=api_flow, force=False, force_graph_sync=True)
    return True


def known_package_flow(ecosystem: str, package: str, version: str) -> bool:
    """Known Package flow.Trigger componentApiFlow."""
    server_create_component_bookkeeping(
        ecosystem, package, version, g.decoded_token)
    return True


def ca_validate_input(input_json: Dict, ecosystem: str) -> List[Dict]:
    """Validate CA Input."""
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
    for pkg in input_json.get('package_versions'):
        package = pkg.get("package")
        version = pkg.get("version")
        if not all([package, version]):
            error_msg = "Invalid Input: Package, Version are required."
            raise BadRequest(error_msg)

        if not (isinstance(version, str) and isinstance(package, str)):
            error_msg = "Package version should be string format only."
            raise BadRequest(error_msg)

        if not validate_version(version):
            error_msg = "Package version should not have special characters."
            raise BadRequest(error_msg)

        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)

        package = case_sensitivity_transform(ecosystem, package)
        packages_list.append({"name": package, "version": version})

    return packages_list


def get_ca_batch_response(ecosystem: str, packages: List[Dict]) -> Tuple[Dict, Set]:
    """Fetch analysis for given package+version from the graph database.

    This Function does 2 actions:
    1. Queries GraphDB to fetch Package info
    2. Calculates Unknown Packages

    :param ecosystem: Ecosystem.
    :param packages: List of dict of package, version info.

    :returns: Graph Response, Unknown Packages
    """
    logger.debug('Executing CA Batch Vendor Specific Analyses')
    graph_response: Dict = GraphAnalyses().get_batch_ca_data(ecosystem, packages)
    analyzed_dependencies: Set = set(analysed_package_details(graph_response))
    unknown_pkgs: Set = get_all_unknown_packages(analyzed_dependencies, packages)
    return graph_response, unknown_pkgs


def analysed_package_details(graph_response: Dict) -> Set:
    """Analyses Package Details from GraphDB.

    Converts GraphDb output packages into set of Normalised hashable Packages
    :param graph_response: Graph DB Response
    :return: set of hashable Packages
    """
    db_pkg_list = []
    for pack_details in graph_response.get('result').get('data'):
        pkg_name = pack_details.get('package').get('name', [''])[0]
        pkg_vr = pack_details.get('version').get('version', [''])[0]
        db_pkg_list.append({"name": pkg_name, "version": pkg_vr})
    db_known_packages = normlize_packages(db_pkg_list)
    return set(db_known_packages)


def get_all_unknown_packages(analyzed_dependencies: Set, packages: List) -> Set:
    """Get all unknowns packages.

    unknown_packages = input_packages - graphdb_output_packages
    :param analyzed_dependencies: Analyses Packages in GraphDB Response
    :param packages: Packages List

    :return: Set of Unknown Packages
    """
    normalized_packages = normlize_packages(packages)
    input_dependencies = set(normalized_packages)

    return input_dependencies.difference(analyzed_dependencies)
