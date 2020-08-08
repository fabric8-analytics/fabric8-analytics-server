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
import re
from collections import namedtuple
from typing import Dict, Set, List, Optional, Tuple
from flask import g
from bayesian.exceptions import HTTPError
from bayesian.utility.db_gateway import GraphAnalyses
from bayesian.utility.v2.ca_response_builder import CABatchResponseBuilder
from bayesian.utils import check_for_accepted_ecosystem, server_create_analysis
from f8a_worker.utils import MavenCoordinates, case_sensitivity_transform


logger = logging.getLogger(__name__)
Package = namedtuple("Package", ["name", "version"])


def validate_version(version: str) -> bool:
    """Version should not contain special Characters."""
    if re.findall('[!@#$%^&*()]', version):
        return False
    return True


def get_package_version(pkg_obj: Dict, ecosystem: str) -> Tuple[str, str]:
    """Fetch, Clean and Validate Package Version Info from Input.

    :param pkg_obj: Package Info from User
    :param ecosystem: Ecosystem Info Provided by User
    :return: package, version
    """
    package: str = pkg_obj.get('package')
    version: str = pkg_obj.get('version')

    if not all([ecosystem, package, version]):
        raise HTTPError(422, "Invalid Input: Package, Version and Ecosystem are required.")

    if not validate_version(version):
        msg: dict = {'message': "Package version should not have special characters."}
        return HTTPError(400, msg)

    if ecosystem == 'maven':
        package = MavenCoordinates.normalize_str(package)

    package = case_sensitivity_transform(ecosystem, package)
    return package, version


def normlize_packages(packages: List[Dict]) -> List[Package]:
    """Normalise Packages into hashable."""
    return [Package(p['name'], p['version']) for p in packages]


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple], api_flow: bool) -> bool:
    """Unknown Package flow."""
    for pkg in unknown_pkgs:
        # Enter the unknown path: Trigger bayesianApiFlow
        server_create_analysis(ecosystem, pkg.name, pkg.version, user_profile=g.decoded_token,
                               api_flow=api_flow, force=False, force_graph_sync=True)
    return True


def ca_validate_input(input_json):
    """Validate CA Input. Move Out to Utiltity."""
    if not input_json:
        raise HTTPError(400, error="Expected JSON request")

    if not isinstance(input_json, dict):
        raise HTTPError(400, error="Expected list of dependencies in JSON request")

    ecosystem = input_json.get('ecosystem')
    if not check_for_accepted_ecosystem(ecosystem):
        error_msg: str = f"Ecosystem {ecosystem} is not supported for this request"
        raise HTTPError(400, error=error_msg)

    if not input_json.get('package_versions'):
        error_msg: str = "package_versions is missing"
        raise HTTPError(400, error=error_msg)

    return True


def get_ca_batch_response(ecosystem: str, packages: List[Dict]) -> Optional[Tuple]:
    """Fetch analysis for given package+version from the graph database.

    This Function does 3 things:
    1. Queries GraphDB to fetch Package info
    2. Calculates Unknown Packages
    3. Buids Recommendation.

    :param ecosystem: Ecosystem.
    :param packages: List of dict of package, version info.

    :returns: Json Response
    """
    logger.debug('Executing CA Batch Vendor Specific Analyses')
    try:
        graph_response: Dict = GraphAnalyses().get_batch_ca_data(ecosystem, packages)

        analyzed_dependencies: Set = set(analysed_package_details(graph_response))
        unknown_pkgs: Set = get_all_unknown_packages(analyzed_dependencies, packages)
        result: List = [
            CABatchResponseBuilder(ecosystem).generate_recommendation(package)
            for package in graph_response.get('result', {}).get('data')
        ]
        return result, unknown_pkgs

    except Exception as e:
        logger.error(str(e))
        raise HTTPError(400, "Internal Server Exception. "
                             "Please contact us if problem persists.")


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
