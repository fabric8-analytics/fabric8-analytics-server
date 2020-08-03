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
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""Utility function from API v2."""

from urllib.parse import quote
import logging
from bayesian.utility.db_gateway import GraphAnalyses
from bayesian.utils import version_info_tuple, convert_version_to_proper_semantic, server_create_analysis
from typing import Dict, List, Tuple, Union, Set
import re
from collections import namedtuple, defaultdict
from abc import ABC
from flask import g


logger = logging.getLogger(__name__)


def validate_version(version):
    """Version should not contain special Characters."""

    if re.findall('[!@#$%^&*()]', version):
        return False
    return True


def unknown_package_flow(ecosystem: str, unknown_pkgs: Set[namedtuple], api_flow: bool) -> bool:
    """Unknown Package flow."""
    for pkg in unknown_pkgs:
        # Enter the unknown path: Trigger bayesianApiFlow
        server_create_analysis(ecosystem, pkg.name, pkg.version, user_profile=g.decoded_token,
                               api_flow=api_flow, force=False, force_graph_sync=True)
    return True


class NormalizedPackages:
    """Duplicate free Package List."""

    def __init__(self, packages: List):
        """Create NormalizedPackages by removing all duplicates from packages."""
        self._packages = packages
        self._pkg_list = []
        Package = namedtuple("Package", ["name", "version"])
        for pkg in packages:
            package_obj = Package(name=pkg['name'], version=pkg['version'])
            self._pkg_list.append(package_obj)

    @property
    def all_packages(self) -> List:
        """All Packages."""
        return self._pkg_list



class ComponentAnalyses:
    """Vendor specific class for Component Analyses API v2."""

    def __init__(self, ecosystem, package, version):
        """For Flows related to Security Vendor Integrations."""
        self.ecosystem = ecosystem
        self.version = version
        self.package = package
        self.recommendation = dict()
        self.response_data = dict()

    @staticmethod
    def is_package_known(query_result) -> bool:
        """Check if Package is Known or Unknown.

        :return:
            - True: Package info exists in GraphDb.
            - False: Package info doesn't exists in Graphdb.
        """
        logger.info("Checking if package is known.")
        if query_result is None:
            return False
        result_data = query_result.get('result', {}).get('data')
        if not (result_data and len(result_data) > 0):
            return False
        return True

    def get_component_analyses_response(self) -> Union[dict, None]:
        """Fetch analysis for given package+version from the graph database.

        Fetch analysis for given package+version from the graph database.
        Main Package for Building Vendor Response.
        It finally builds and returns JSON Response. This is vendor specific Function.
        :returns:
            - Json Response
            - None: On exceptions.
        """
        logger.info('Executing Vendor Specific Analyses')
        try:
            graph_response = GraphAnalyses.get_ca_data_from_graph(
                self.ecosystem, self.package, self.version, vendor='snyk')
            if not self.is_package_known(graph_response):
                # Trigger Unknown Flow on Unknown Packages
                logger.info(f"Package {self.package} is not known.")
                return None
            return ComponentAnalysisResponseBuilder(
                self.ecosystem, self.package, self.version).generate_recommendation(graph_response)

        except Exception as e:
            logger.error('ERROR: %s', str(e))
            return None



class CABatchCall:
    """Namespace for Component Analyses Batch call"""

    def __init__(self, ecosystem: str):
        """For Flows related to Security Vendor Integrations."""
        self.ecosystem = ecosystem
        self.packages = []
        self.recommendation = dict()
        self.response_data = dict()

    def get_ca_batch_response(self, packages: List[Dict]) -> Union[Tuple, None]:
        """Fetch analysis for given package+version from the graph database.

        Build CA Batch Response.
        Result is fed to ResponseBuilder.
        :param packages: List of dict of package, version info.

        :returns:
            - Json Response
            - None: Exception/Package not Known.
        """
        logger.info('Executing CA Batch Vendor Specific Analyses')
        self.packages = packages
        try:
            graph_response = GraphAnalyses().get_batch_ca_data(self.ecosystem, packages, 'ca_batch')

            analyzed_dependencies = set(self._analysed_package_details(graph_response))
            unknown_pkgs: Set = self.get_all_unknown_packages(analyzed_dependencies)
            result = []
            for package in analyzed_dependencies:
                result.append(CABatchResponseBuilder(
                    self.ecosystem, package.name, package.version).generate_recommendation(graph_response))

            return result, unknown_pkgs

        except Exception as e:
            logger.info("Error")
            logger.error(str(e))
            return None, None

    @staticmethod
    def _analysed_package_details(graph_response: Dict) -> Set:
        """Analyses Package Details from GraphDB

        Converts GraphDb output packages into list of Normalised Packages
        :param graph_response: Graph DB Response
        :return: list of Normalised Packages
        """
        db_pkg_list = []
        for pack_details in graph_response.get('result').get('data'):
            pkg_name = pack_details.get('package').get('name', [''])[0]
            pkg_vr = pack_details.get('version').get('version', [''])[0]
            db_pkg_list.append({"name": pkg_name, "version": pkg_vr})
        _normalized_packages = NormalizedPackages(db_pkg_list)
        db_known_packages = _normalized_packages.all_packages
        return set(db_known_packages)

    def get_all_unknown_packages(self, analyzed_dependencies: Set) -> Set:
        """Get all unknowns packages.

        unknown_packages = input_packages - graphdb_output_packages
        :param analyzed_dependencies: Analyses Packages in GraphDB Response
        :return: Unknown Packages to Graph
        """
        _normalized_packages = NormalizedPackages(self.packages)
        input_dependencies = set(_normalized_packages.all_packages)

        return input_dependencies.difference(analyzed_dependencies)


class AbstractBaseClass(ABC):
    """Abstract Class for CA Response Builder."""

    def __init__(self, ecosystem, package, version):
        """Response Builder, Build Json Response for Component Analyses."""
        self.ecosystem = ecosystem
        self.version = version
        self.package = package
        self._cves = list()
        self.severity = ""
        self.nocve_version = ""
        self.public_vul = 0
        self.pvt_vul = 0

    def generate_recommendation(self, graph_response):
        """Abstract generate_recommendation func"""
        pass

    def get_message(self) -> str:
        """Build Message.

        Message to be shown in Component Analyses Tooltip.
        :return: Message string.
        """
        message = f"{self.package} - {self.version} has "

        if self.public_vul and self.pvt_vul:
            # Add Private Vulnerability and Public Vul Info only
            message += f"{self.public_vul} known security vulnerability "
            message += f"and {self.pvt_vul} security advisory with {len(self.severity)} " \
                       f"having {self.severity[0]} severity. "

            message += self.get_recommendation()
            return message

        elif self.public_vul:
            # Add Public Vulnerability Info only
            message += f"{self.public_vul} known security vulnerability"

            message += self.append_with_severity_count(self.public_vul)

            message += f" having {self.severity[0]} severity. "

            message += self.get_recommendation()
            return message

        elif self.pvt_vul:
            # Add Private Vulnerability Info only
            message += f"{self.pvt_vul} security advisory"

            message += self.append_with_severity_count(self.pvt_vul)

            message += f" having {self.severity[0]} severity. "
        return message

    def append_with_severity_count(self, vul_count) -> str:
        """Append 'with {number} to message."""
        if vul_count != len(self.severity):
            message = f" with {len(self.severity)}"
            return message
        return ""

    def get_recommendation(self) -> str:
        """Generate Recommendation message."""
        if not self.nocve_version:
            message = 'No recommended version.'
            return message

        message = f'Recommendation: use version {self.nocve_version}.'
        return message

    def get_version_without_cves(self, latest_non_cve_versions):
        """Return higher version which doesn't have any CVEs. None if there is no such version.

        :return: Highest Version out of all latest_non_cve_versions.
        """
        logger.info("All Versions with Vulnerabilities.")
        input_version_tuple = version_info_tuple(
            convert_version_to_proper_semantic(self.version)
        )
        highest_version = ''
        for version in latest_non_cve_versions:

            graph_version_tuple = version_info_tuple(
                convert_version_to_proper_semantic(version)
            )
            if graph_version_tuple > input_version_tuple:
                if not highest_version:
                    highest_version = version
                highest_version_tuple = version_info_tuple(
                    convert_version_to_proper_semantic(highest_version)
                )
                # If version to recommend is closer to what a user is using then, use less than
                # If recommendation is to show highest version then, use greater than
                if graph_version_tuple > highest_version_tuple:
                    highest_version = version
        return highest_version

    def has_cves(self):
        """Check if package has Vulnerability.

        :return: True - Package has vulnerability.
                False - Package has no vulnerability.
        """
        logger.info("Checking vulnerabilities.")
        return bool(self._cves)

    def generate_response(self):
        """Abstract function for Generate Response.."""
        pass

    def get_vulnerabilities_count(self):
        """Vulnerability count, Calculates Public and Pvt Vulnerability count.

        Populates Private and Public vulnerability count.
        :return: None
        """
        logger.info("Get Vulnerabilities count.")
        public_vul = 0
        pvt_vul = 0
        try:
            for cve in self._cves:
                if cve['snyk_pvt_vulnerability'][0]:
                    pvt_vul += 1
                else:
                    public_vul += 1
        except Exception:
            logger.error(f"snyk_pvt_vulnerability key not found for "
                         f"{self.package}, {self.version}, {self.ecosystem}")
            pass

        return public_vul, pvt_vul

    def get_link(self):
        """Generate link to Snyk Vulnerability Page.

        :return: Vendor Vulnerability link.
        """
        logger.info('Generate Vendor Vulnerability link')
        snyk_ecosystem = {
            'maven': 'maven',
            'pypi': 'pip',
            'npm': 'npm'
        }
        return f"https://snyk.io/vuln/{snyk_ecosystem[self.ecosystem]}:{quote(self.package)}"

    @staticmethod
    def get_registration_link():
        """Registration link for Free User.

        :return: Snyk Registration link
        """
        return "https://app.snyk.io/login"

    def get_exploitable_cves_counter(self):
        """Calculate total exploitable Vulnerabilities.

        possible_values = ["Not Defined", "Unproven", "Proof of Concept", "Functional", "High"]
        :return: Exploitable Vulnerability counter.
        """
        logger.info("Generating Exploitable Vulnerabilities Count.")
        exploitable_exploits = ["Proof of Concept", "Functional", "High"]
        exploit_counter = 0
        try:
            for cve in self._cves:
                if 'exploit' in cve.keys() and cve['exploit'][0] in exploitable_exploits:
                    exploit_counter += 1
        except IndexError:
            logger.error(f"Exploit not found for EPV: "
                         f"{self.ecosystem}, {self.package}, {self.version}")
            return None
        return exploit_counter

    def get_total_vulnerabilities(self):
        """Find total number of Vulnerabilities.

        :return: Int - total vulnerabilities counter.
        """
        logger.info("Get total Vulnerabilities.")
        return len(self._cves)

    def get_severity(self) -> list:
        """Severity Calculator.

        We have predefined expected severity values from vendor
        This method returns list of highest severity present in input.
        Ex ['high', 'high', 'low' ] -> ['high', 'high']

        :return: Highest ranking severities among all input_severities.
        """
        logger.info("Get maximum severity.")
        try:
            # Fetch all severities from Input
            input_severities = [cve['severity'][0] for cve in self._cves
                                if 'severity' in cve.keys()]
        except IndexError:
            logger.error(f"Severity not found for EPV: "
                         f"{self.ecosystem}, {self.package}, {self.version}")
            return []

        # All conditional checks are in order of precedence.
        if 'critical' in input_severities:
            highest_severity_name_in_input = 'critical'
        elif 'high' in input_severities:
            highest_severity_name_in_input = 'high'
        elif 'medium' in input_severities:
            highest_severity_name_in_input = 'medium'
        elif 'low' in input_severities:
            highest_severity_name_in_input = 'low'
        else:
            raise Exception(f"Invalid Severity value for epv "
                            f"{self.ecosystem},{self.package} and {self.version} ")

        # List out all highest_severity_name_in_input in input_severities.
        return list(filter(lambda x: x == highest_severity_name_in_input, input_severities))

    def get_cve_maps(self):
        """Abstract get_cve_maps."""
        pass


class ComponentAnalysisResponseBuilder(AbstractBaseClass):
    """Vendor specific response builder for Component Analyses v2."""

    def generate_recommendation(self, graph_response: Dict) -> Dict:
        """Generate recommendation for the package+version.

        Main function to generate recommendation response.

        :return: Json Response
        """
        logger.info("Generating Recommendation")
        result_data = graph_response.get('result', {}).get('data')
        latest_non_cve_versions = result_data[0].get('package', {}).get(
            'latest_non_cve_version', [])
        for data in result_data:
            this_version = data.get('version', {}).get('version', [None])[0]
            if this_version == self.version:
                if 'cve' in data:
                    self._cves.append(data.get('cve'))

        if (not self.has_cves()) or not bool(latest_non_cve_versions):
            # If Package has No cves or No Latest Non CVE Versions.
            return dict(recommendation={})

        self.nocve_version: list = self.get_version_without_cves(latest_non_cve_versions)
        self.public_vul, self.pvt_vul = self.get_vulnerabilities_count()
        self.severity:list = self.get_severity()
        return self.generate_response()

    def generate_response(self) -> Dict:
        """Build a JSON Response from all calculated values.

        :return: json formatted response to requester.
        """
        logger.info("Generating Final Response.")
        component_analyses_dict = dict(
            vulnerability=self.get_cve_maps()
        )
        response = dict(
            recommended_versions=self.nocve_version,
            registration_link=self.get_registration_link(),
            component_analyses=component_analyses_dict,
            message=self.get_message(),
            severity=self.severity[0],
            known_security_vulnerability_count=self.public_vul,
            security_advisory_count=self.pvt_vul,
        )
        return response

    def get_cve_maps(self) -> List[Dict]:
        """Get all Vulnerabilities Meta Data.

        :return: List
            - Empty: if no Vulnerability is there.
            - Dict: if Vulnerability is present.
        """
        logger.info("Get Vulnerability Meta data.")
        cve_list = []
        for cve in self._cves:
            cve_list.append(dict(
                vendor_cve_ids=cve.get('snyk_vuln_id', [None])[0],
                cvss=str(cve.get('cvss_scores', [None])[0]),
                is_private=cve.get('snyk_pvt_vulnerability', [None])[0],
                cwes=cve.get('snyk_cwes', []),
                cvss_v3=cve.get('snyk_cvss_v3', [None])[0],
                severity=cve.get('severity', [None])[0],
                title=cve.get('title', [None])[0],
                url=cve.get('snyk_url', [None])[0],
                cve_ids=cve.get('snyk_cve_ids', []),
                fixed_in=cve.get('fixed_in', [])
            ))
        return cve_list



class CABatchResponseBuilder(AbstractBaseClass):
    """Response builder for Component Analyses v2 Batch."""

    def generate_recommendation(self, graph_response: Dict) -> Dict:
        """Generate recommendation for the package+version.

        Main function to generate recommendation response.

        :return: Json Response
        """
        logger.info("Generating Recommendation")
        result_data: Dict = graph_response.get('result', {}).get('data')
        latest_non_cve_versions: List[str] = result_data[0].get('package', {}).get(
            'latest_non_cve_version', [])

        for data in result_data:
            this_version = data.get('version', {}).get('version', [None])[0]

            if this_version != self.version:
                logger.info("Pkg version doesn't match with Graph Results.")
                continue

            if 'cve' not in data:
                logger.info("No Vulnerability Info found.")
                continue

            for cve_data in data.get('cve'):
                self._cves.append(cve_data)

        if (not self.has_cves()) or not bool(latest_non_cve_versions):
            # If Package has No cves or No Latest Non CVE Versions.
            logger.info("No Vulnerabilities found.")
            return dict(recommendation={})

        self.nocve_version: List[str] = self.get_version_without_cves(latest_non_cve_versions)
        self.public_vul, self.pvt_vul = self.get_vulnerabilities_count()
        self.severity: List[str] = self.get_severity()
        return self.generate_response()

    def get_cve_maps(self) -> List[Dict]:
        """Get all Vulnerabilities Meta Data.

        :return: List
            - Empty: if no Vulnerability is there.
            - Dict: if Vulnerability is present.
        """
        logger.info("Get Vulnerability Meta data.")
        cve_list = [dict(
                id=cve.get('snyk_vuln_id', [None])[0],
                cvss=str(cve.get('cvss_scores', [None])[0]),
                is_private=cve.get('snyk_pvt_vulnerability', [None])[0],
                cwes=cve.get('snyk_cwes', []),
                cvss_v3=cve.get('snyk_cvss_v3', [None])[0],
                severity=cve.get('severity', [None])[0],
                title=cve.get('title', [None])[0],
                url=cve.get('snyk_url', [None])[0],
                cve_ids=cve.get('snyk_cve_ids', []),
                fixed_in=cve.get('fixed_in', [])
            ) for cve in self._cves]
        return cve_list

    def generate_response(self) -> Dict:
        """Build a JSON Response from all calculated values.

        :return: json formatted response to requester.
        """
        logger.info("Generating Final Response.")
        response = dict(
            package=self.package,
            version=self.version,
            recommended_versions=self.nocve_version,
            registration_link=self.get_registration_link(),
            vulnerability=self.get_cve_maps(),
            message=self.get_message(),
            highest_severity=self.severity[0],
            known_security_vulnerability_count=self.public_vul,
            security_advisory_count=self.pvt_vul,
        )
        return response