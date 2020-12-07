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
from f8a_utils.tree_generator import GolangDependencyTreeGenerator
from f8a_utils.gh_utils import GithubUtils
from flask import g
from bayesian.utility.v2.ca_response_builder import CABatchResponseBuilder
from bayesian.utils import check_for_accepted_ecosystem, \
    server_create_analysis, server_create_component_bookkeeping
from f8a_worker.utils import MavenCoordinates
from werkzeug.exceptions import BadRequest
from bayesian.utility.db_gateway import GraphAnalyses
from requests_futures.sessions import FuturesSession

logger = logging.getLogger(__name__)
Package = namedtuple("Package", ["name", "given_name", "version", "package_unknown",
                                 "given_version", "is_pseudo_version"])

_APP_SECRET_KEY = os.getenv('APP_SECRET_KEY', 'not-set')
_INGESTION_API_URL = "http://{host}:{port}/{endpoint}".format(
    host=os.environ.get("INGESTION_SERVICE_HOST", "bayesian-jobs"),
    port=os.environ.get("INGESTION_SERVICE_PORT", "34000"),
    endpoint='ingestions/epv')
worker_count = int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100'))
_session = FuturesSession(max_workers=worker_count)


def validate_version(version: str) -> bool:
    """Version should not contain special Characters."""
    logger.debug('Version validator.')
    if re.findall('[!@#$%^&*()]', version):
        return False
    return True


def normlize_packages(name: str, given_name: str,
                      version: str, given_version: str,
                      is_pseudo_version: bool) -> Package:
    """Normalise Packages into hashable."""
    logger.debug('Normalizing Packages.')
    return Package(
        name=name, given_name=given_name,
        version=version, given_version=given_version,
        is_pseudo_version=is_pseudo_version, package_unknown=True)


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple]) -> bool:
    """Unknown Package flow. Trigger bayesianApiFlow."""
    logger.debug('Triggered Unknown Package Flow.')
    started_at = time.time()
    logger.info('ecosystem {}'.format(ecosystem))
    logger.info('unknown_pkgs {}'.format(unknown_pkgs))

    payload = {
        "ecosystem": ecosystem,
        "packages": [],
        "force": False,
        "force_graph_sync": True
    }

    for pkg in unknown_pkgs:
        payload['packages'].append({'package': pkg.name, 'version': pkg.version})
        server_create_component_bookkeeping(ecosystem, pkg.name, pkg.version, g.decoded_token)

    logger.info('payload = {}'.format(payload))

    _session.post(url=_INGESTION_API_URL,
                  json=payload,
                  headers={'auth_token': _APP_SECRET_KEY})

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

    gh = GithubUtils()
    packages_list = []
    normalised_input_pkgs = []
    for pkg in input_json.get('package_versions'):
        pseudo_version = False
        package = given_package = pkg.get("package")
        clean_version = given_version = pkg.get("version")
        if not all([package, given_version]):
            error_msg = "Invalid Input: Package, Version are required."
            raise BadRequest(error_msg)

        if (not isinstance(given_version, str)) or (not isinstance(package, str)):
            error_msg = "Package version should be string format only."
            raise BadRequest(error_msg)

        if not validate_version(given_version):
            error_msg = "Package version should not have special characters."
            raise BadRequest(error_msg)

        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)

        if ecosystem == 'pypi':
            package = package.lower()

        if ecosystem == 'golang':
            _, clean_version = GolangDependencyTreeGenerator.clean_version(given_version)
            pseudo_version = gh.is_pseudo_version(clean_version)
            # Strip module appended to the package name
            package = package.split('@')[0]

        packages_list.append(
            {"name": package, "given_name": given_package,
             "version": clean_version, "given_version": given_version,
             "is_pseudo_version": pseudo_version})
        normalised_input_pkgs.append(normlize_packages(package, given_package, clean_version,
                                                       given_version, pseudo_version))
    return packages_list, normalised_input_pkgs


def get_batch_ca_data(ecosystem: str, packages) -> dict:
    """Fetch package details for component analyses."""
    logger.debug('Executing get_batch_ca_data')
    started_at = time.time()

    response = None
    semver_packages = []
    pseudo_version_packages = []

    # Need to seperate semver and pseudo verion packages for golang
    if (ecosystem == "golang"):
        for p in packages:
            if p['is_pseudo_version']:
                pseudo_version_packages.append(p)
            else:
                semver_packages.append(p)
    else:
        semver_packages = packages

    if len(semver_packages) > 0:
        response = GraphAnalyses.get_batch_ca_data(ecosystem, semver_packages)

    if len(pseudo_version_packages) > 0:
        pseudo_response = GraphAnalyses.get_batch_ca_data_for_pseudo_version(
            ecosystem, pseudo_version_packages)
        # Merge both data into one.
        if response:
            response['result']['data'] += pseudo_response['result']['data']
        else:
            response = pseudo_response

    elapsed_time = time.time() - started_at
    logger.info("It took %s to fetch results from Gremlin.", elapsed_time)

    return response if response else {}


def get_known_unknown_pkgs(
        ecosystem: str, graph_response: Dict,
        normalised_input_pkgs: List) -> Tuple[List[Dict], Set[Package]]:
    """Analyse Known and Unknown Packages.

    :param ecosystem: Ecosystem
    :param graph_response: Graph Response
    :param normalised_input_pkgs: Normalised Input Packages
    :return: Stack Recommendations, Unknown Pkgs
    """
    normalised_input_pkg_map = None  # Mapping is required only for Golang.
    if ecosystem == 'golang':
        normalised_input_pkg_map = {
            input_pkg.name: {
                'given_name': input_pkg.given_name,
                'version': input_pkg.version,
                'given_version': input_pkg.given_version
            } for input_pkg in normalised_input_pkgs}
    stack_recommendation = []
    db_known_packages = set()
    gh = GithubUtils()
    for package in graph_response.get('result', {}).get('data'):
        pkg_name = package.get('package').get('name', [''])[0]
        clean_version = get_clean_version(pkg_name,
                                          package.get('version').get('version', [''])[0],
                                          normalised_input_pkg_map)
        pseudo_version = gh.is_pseudo_version(clean_version) if ecosystem == 'golang' else False
        given_pkg_name, given_pkg_version = get_given_name_and_version(pkg_name, clean_version,
                                                                       normalised_input_pkg_map)
        pkg_recomendation = CABatchResponseBuilder(ecosystem). \
            generate_recommendation(package, given_pkg_name, given_pkg_version)
        stack_recommendation.append(pkg_recomendation)
        known_package_flow(ecosystem, pkg_name, clean_version)
        db_known_packages.add(normlize_packages(name=pkg_name, given_name=given_pkg_name,
                                                version=clean_version,
                                                given_version=given_pkg_version,
                                                is_pseudo_version=pseudo_version))

    input_dependencies = set(normalised_input_pkgs)
    unknown_pkgs: Set = input_dependencies.difference(db_known_packages)
    return stack_recommendation, unknown_pkgs


def get_clean_version(pkg_name: str, pkg_version: str, normalised_input_pkg_map=None) -> str:
    """Output clean package version for each Package.

    :param pkg_name: Package Name
    :param normalised_input_pkg_map: Input Package Map
    :return: Given clean package version
    """
    logger.debug('Fetch input clean package version.')
    if isinstance(normalised_input_pkg_map, dict):
        return normalised_input_pkg_map[pkg_name]['version']
    return pkg_version


def get_given_name_and_version(pkg_name: str, pkg_version: str,
                               normalised_input_pkg_map=None) -> (str, str):
    """Output given package name and version in the request.

    :param pkg_name: Package Name
    :param normalised_input_pkg_map: Input Package Map
    :param pkg_version: Clean Package Version
    :return: Given Package version (By User)
    """
    logger.debug('Fetch Input Package version.')
    if isinstance(normalised_input_pkg_map, dict):
        normalised_input_pkg = normalised_input_pkg_map.get(pkg_name, None)
        if normalised_input_pkg:
            return normalised_input_pkg['given_name'], normalised_input_pkg['given_version']
    return pkg_name, pkg_version


def add_unknown_pkg_info(stack_recommendation: List, unknown_pkgs: Set[Package]) -> List:
    """Add Unknown Package Info in stack_recommendation.

    :param stack_recommendation:
    :param unknown_pkgs:
    :return: Updated Stack Recommendation
    """
    for unknown_pkg in unknown_pkgs:
        unknowns = unknown_pkg._asdict()
        unknowns['version'] = unknowns.get('given_version')
        unknowns.pop('given_version', None)
        unknowns['name'] = unknowns.get('given_name')
        unknowns.pop('given_name', None)
        unknowns.pop('is_pseudo_version', None)
        stack_recommendation.append(dict(unknowns))
    return stack_recommendation
