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
from f8a_utils.user_token_utils import UserStatus
from bayesian.utils import version_info_tuple, convert_version_to_proper_semantic
from typing import Dict, List, Optional
from collections import namedtuple
from abc import ABC
from flask import g

logger = logging.getLogger(__name__)
Package = namedtuple("Package", ["name", "version"])


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

    def get_component_analyses_response(self) -> Optional[Dict]:
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


class ComponentResponseBase(ABC):
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
        """Abstract generate_recommendation func."""
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
            'npm': 'npm',
            'golang': 'golang',
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


class ComponentAnalysisResponseBuilder(ComponentResponseBase):
    """Vendor specific response builder for Component Analyses v2."""

    def generate_recommendation(self, graph_response: Dict) -> Dict:
        """Generate recommendation for the package+version.

        Main function to generate recommendation response.

        :return: Json Response
        """
        logger.debug("Generating Recommendation")
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
        self.severity: list = self.get_severity()
        return self.generate_response()

    def generate_response(self) -> Dict:
        """Build a JSON Response from all calculated values.

        :return: json formatted response to requester.
        """
        logger.debug("Generating Final Response.")
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
        logger.debug("Get Vulnerability Meta data.")
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


class CABatchResponseBuilder(ComponentResponseBase):
    """Response builder for Component Analyses v2 Batch."""

    def __init__(self, ecosystem):
        """Batch CA Response Builder."""
        super().__init__(ecosystem, None, None)

    def generate_recommendation(
            self, package_graph_response: Dict,
            given_name: str = None, given_version: str = None) -> Dict:
        """Generate recommendation for the package+version.

        Main function to generate recommendation response.

        :param package_graph_response: Individual Package Object from Gremlin
        :param given_name: Full package name as given in the request
        :param given_version: Version from User Input
        :return: Json Response
        """
        logger.debug("Generating Recommendation")
        self.version = given_version
        self.package = given_name
        latest_non_cve_versions: List[str] = package_graph_response.get('package', {}).get(
            'latest_non_cve_version', [])
        self._cves = package_graph_response.get('cve')

        if (not self.has_cves()) or not bool(latest_non_cve_versions):
            # If Package has No cves or No Latest Non CVE Versions.
            logger.debug("No Vulnerabilities found.")
            return dict(
                package=self.package,
                version=self.version,
                package_unknown=False,
                recommendation={})

        if self.ecosystem == 'golang':
            # Prefix recommendation version with 'v' for golang
            recm_version = self.get_version_without_cves(latest_non_cve_versions)
            self.nocve_version: List[str] = 'v' + recm_version if recm_version != '' else ''
        else:
            self.nocve_version: List[str] = self.get_version_without_cves(latest_non_cve_versions)
        self.public_vul, self.pvt_vul = self.get_vulnerabilities_count()
        self.severity: List[str] = self.get_severity()

        if g.user_status == UserStatus.REGISTERED:
            return self.get_premium_response()
        return self.generate_response()

    def get_cve_maps(self) -> List[Dict]:
        """Get all Vulnerabilities Meta Data.

        :return: List
            - Empty: if no Vulnerability is there.
            - Dict: if Vulnerability is present.
        """
        logger.debug("Get Vulnerability Meta data.")
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

    def get_premium_response(self) -> Dict:
        """Get Premium Response.

        :return: Dict of Registered User Response.
        """
        exploitable_vuls = self.get_exploitable_cves_counter()
        logger.debug("Generating Premium Response.")
        response = dict(
            package_unknown=False,
            package=self.package,
            version=self.version,
            recommended_versions=self.nocve_version,
            vendor_package_link=self.get_link(),
            vulnerability=self.get_cve_maps(),
            message=self.get_premium_message(exploitable_vuls),
            highest_severity=self.severity[0],
            known_security_vulnerability_count=self.public_vul,
            security_advisory_count=self.pvt_vul,
            exploitable_vulnerabilities_count=exploitable_vuls
        )
        return response

    def get_premium_message(self, exploitable_vuls: int) -> str:
        """Build Message for Registered User.

        Message to be shown in Component Analyses Tooltip.
        :return: Message string.
        """
        message = f"{self.package} - {self.version} has "

        if self.public_vul and self.pvt_vul:
            # Add Private Vulnerability and Public Vul Info only
            message += f"{self.public_vul} known security vulnerability "
            message += f"and {self.pvt_vul} security advisory with "
            message += self.append_with_exploit_details(exploitable_vuls)
            message += f"{self.severity[0]} severity. "
            message += self.get_recommendation()
            return message

        if self.public_vul:
            # Add Public Vulnerability Info only
            message += f"{self.public_vul} known security vulnerability with "
            message += self.append_with_exploit_details(exploitable_vuls)
            message += f"{self.severity[0]} severity. "
            message += self.get_recommendation()
            return message

        if self.pvt_vul:
            # Add Private Vulnerability Info only
            message += f"{self.pvt_vul} security advisory with "
            message += self.append_with_exploit_details(exploitable_vuls)
            message += f"{self.severity[0]} severity. "
            message += self.get_recommendation()
        return message

    def append_with_exploit_details(self, exploitable_vuls) -> str:
        """Append exploit details to message."""
        if exploitable_vuls:
            return f"{exploitable_vuls} exploitable vulnerability and "
        return ""

    def generate_response(self) -> Dict:
        """Build a JSON Response from all calculated values.

        :return: json formatted response to requester.
        """
        logger.debug("Generating Final Response.")
        response = dict(
            package_unknown=False,
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
