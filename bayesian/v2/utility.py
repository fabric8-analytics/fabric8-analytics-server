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
from bayesian.v2.communicator import GraphAnalyses
import semantic_version as sv


logger = logging.getLogger(__file__)


class Adequacy:
    """Utility Class for varied Utility functions."""

    @staticmethod
    def version_info_tuple(version):
        """Return version information in form of (major, minor, patch, build) for a given Version.

        : type version: semantic_version.base.Version
        : param version: The semantic version whole details are needed.
        : return: A tuple in form of Version.(major, minor, patch, build)
        """
        if type(version) == sv.base.Version:
            return (version.major,
                    version.minor,
                    version.patch,
                    version.build)
        return (0, 0, 0, tuple())

    @staticmethod
    def convert_version_to_proper_semantic(version, package_name=None):
        """Perform Semantic versioning.

        : type version: string
        : param version: The raw input version that needs to be converted.
        : type return: semantic_version.base.Version
        : return: The semantic version of raw input version.
        """
        conv_version = sv.Version.coerce('0.0.0')
        try:
            if version in ('', '-1', None):
                version = '0.0.0'
            """Needed for maven version like 1.5.2.RELEASE to be converted to
            1.5.2 - RELEASE for semantic version to work."""
            version = version.replace('.', '-', 3)
            version = version.replace('-', '.', 2)
            # Needed to add this so that -RELEASE is account as a Version.build
            version = version.replace('-', '+', 3)
            conv_version = sv.Version.coerce(version)
        except ValueError:
            logger.error(
                "Unexpected ValueError for the package {} due to version {}".format(
                    package_name, version))
            pass
        finally:
            return conv_version


class VendorAnalyses:
    """Vendor specific class for Component Analyses API v2."""

    def __init__(self, ecosystem, package, version):
        """For Flows related to Security Vendor Integrations."""
        self.ecosystem = ecosystem
        self.version = version
        self.package = package
        self.recommendation = dict()
        self.recommended_version = ""
        self.response_data = dict()

    @staticmethod
    def is_package_known(query_result):
        """Check if Package is Known or Unknown.

        :return:
            - True: Package info exists in GraphDb.
            - False: Package info doesn't exists in Graphdb.
        """
        logger.info("Checking if package is known.")
        if query_result is None:
            return False
        result_data = query_result.get('result').get('data')
        if not (result_data and len(result_data) > 0):
            return False
        return True

    def get_vendor_analyses(self):
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
            graph_response = GraphAnalyses(self.ecosystem,
                                           self.package,
                                           self.version).get_data_from_graph()
            if not self.is_package_known(graph_response):
                # Trigger Unknown Flow on Unknown Packages
                logger.info("Package {pkg} is not known.".format(pkg=self.package))
                return None

            logger.info("latest non cve version for is {ver}".format(
                ver=self.recommended_version
            ))
            return ResponseBuilder(
                self.ecosystem, self.package, self.version).generate_recommendation(graph_response)

        except Exception as e:
            logger.error(str(e))
            return None


class ResponseBuilder():
    """Vendor specific response builder for Component Analyses v2."""

    def __init__(self, ecosystem, package, version):
        """Response Builder, Build Json Response for Component Analyses."""
        self.ecosystem = ecosystem
        self.version = version
        self.package = package
        self._cves = list()
        self.cve_dict = dict()
        self.severity = ""
        self.nocve_version = ""
        self.public_vul = 0
        self.pvt_vul = 0

    def generate_recommendation(self, graph_response):
        """Generate recommendation for the package+version.

        Main function to generate recommendation response.

        :return: Json Response
        """
        logger.info("Generating Recommendation")
        result_data = graph_response['result'].get('data')
        latest_non_cve_versions = result_data[0].get('package').get(
                                            'latest_non_cve_version')
        for data in result_data:
            this_version = data.get('version', {}).get('version', [None])[0]
            if this_version == self.version:
                if 'cve' in data:
                    self._cves.append(data.get('cve'))

        if not self.has_cves():
            return dict(recommendation={})
        self.cve_maps = self.get_cve_maps()
        self.nocve_version = self.get_version_without_cves(latest_non_cve_versions)
        self.get_vulnerabilities_count()
        self.get_severity()
        return self.generate_response()

    def get_message(self):
        """Build Message.

        Message to be shown in Component Analyses Tooltip.
        :return: Message string.
        """
        logger.info("Generating Message String.")
        message = "{pkg} - {ver} has {pub_vul} public vulnerability with {svr} severity."
        message += 'Recommendation: use version {rec_ver}.'
        message = message.format(
            pkg=self.package,
            ver=self.version,
            pub_vul=self.public_vul,
            svr=self.severity[0],
            rec_ver=self.nocve_version,
        )
        return message

    def get_version_without_cves(self, latest_non_cve_versions):
        """Return higher version which doesn't have any CVEs. None if there is no such version.

        :return: Highest Version out of all latest_non_cve_versions.
        """
        logger.info("All Versions with Vulnerabilities.")
        util_obj = Adequacy()
        input_version_tuple = util_obj.version_info_tuple(
            util_obj.convert_version_to_proper_semantic(self.version)
        )
        highest_version = ''
        for version in latest_non_cve_versions:
            graph_version_tuple = util_obj.version_info_tuple(
                util_obj.convert_version_to_proper_semantic(version)
            )
            if graph_version_tuple > input_version_tuple:
                if not highest_version:
                    highest_version = version
                highest_version_tuple = util_obj.version_info_tuple(
                    util_obj.convert_version_to_proper_semantic(highest_version)
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
        """Build a JSON Response from all calculated values.

        :return: json formatted response to requester.
        """
        logger.info("Generating Final Response.")
        component_analyses_dict = dict(
            vulnerability=self.cve_maps
        )
        response = dict(
            recommended_versions=self.nocve_version,
            registration_link=self.get_registration_link(),
            component_analyses=component_analyses_dict,
            message=self.get_message(),
            severity=self.severity[0],
            public_vulnerabilities_count=self.public_vul,
            private_vulnerabilities_count=self.pvt_vul,
        )
        return response

    def get_vulnerabilities_count(self):
        """Vulnerability count, Calculates Public and Pvt Vulnerability count.

        Populates Private and Public vulnerability count.
        :return: None
        """
        logger.info("Get Vulnerabilities count.")
        self.public_vul = 0
        self.pvt_vul = 0
        for cve in self._cves:
            if cve['snyk_pvt_vulnerability'][0]:
                self.pvt_vul += 1
            else:
                self.public_vul += 1

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
        return "https://snyk.io/vuln/{}:{}".format(
                snyk_ecosystem[self.ecosystem], quote(self.package))

    @staticmethod
    def get_registration_link():
        """Registration link for Free User.

        :return: Snyk Registration link
        """
        return "https://app.snyk.io/login"

    def get_exploitable_cves(self):
        """Calculate total exploitable Vulnerabilities.

        possible_values = ["Not Defined", "Unproven", "Proof of Concept", "Functional", "High"]
        :return: Exploitable Vulnerability counter.
        """
        logger.info("Generating Exploitable Vulnerabilities Count.")
        exploitable_exploits = ["Proof of Concept", "Functional", "High"]
        exploit_counter = 0
        for cve in self._cves:
            if 'exploit' in cve.keys() and cve['exploit'][0] in exploitable_exploits:
                exploit_counter += 1
        return exploit_counter

    def get_total_vulnerabilities(self):
        """Find total number of Vulnerabilities.

        :return: Int - total vulnerabilities counter.
        """
        logger.info("Get total Vulnerabilities.")
        return len(self._cves)

    def get_severity(self):
        """Severity Calculator.

        severity_levels = { "severity": power_number }
        expected_inputs = {"high", "critical", "severe"}
        :return: list - Highest severity among all vulnerabilities.
        """
        logger.info("Get maximum severity.")
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        input_severities = {cve['severity'][0] for cve in self._cves
                            if 'severity' in cve.keys()}

        if not input_severities.issubset(severity_levels.keys()):
            # Input values contains non recognised values
            return []

        max_severe_value = max(map(lambda x: severity_levels[x], input_severities))
        self.severity = [severity for severity, power_number in severity_levels.items()
                         if power_number == max_severe_value]
        return self.severity

    def get_cve_maps(self):
        """Get all Vulnerabilities Meta Data.

        :return: List
            - Empty: if no Vulnerability is there.
            - Dict: if Vulnerability is present.
        """
        logger.info("Get Vulnerability Meta data.")
        cve_dict = []
        for cve in self._cves:
            cve_dict.append(dict(
                vendor_cve_ids=cve.get('snyk_cve_ids')[0],
                cvss=str(cve.get('cvss_scores')[0]),
                is_private=cve.get('snyk_pvt_vulnerability')[0]
            ))
        return cve_dict
