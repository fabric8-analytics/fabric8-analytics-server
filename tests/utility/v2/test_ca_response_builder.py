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
"""Test Utility for All Utility Functions."""

from bayesian.utility.v2.ca_response_builder import ComponentAnalyses, \
    ComponentAnalysisResponseBuilder, CABatchResponseBuilder
from urllib.parse import quote
from unittest.mock import patch, Mock
import unittest
import pytest
from urllib.parse import urlparse

from bayesian.utility.v2.component_analyses import validate_version


def test_validate_version():
    """Check the function validate_version."""
    assert validate_version("1.2.3")
    assert not validate_version("1.2.*"), "Invalid Version"


class ComponentAnalysesTest(unittest.TestCase):
    """Test Cases for Component Analyses Test class."""

    @staticmethod
    def test_is_package_known_with_None():
        """Test function when package query returns None."""
        result = ComponentAnalyses("eco", "pkg", "ver").is_package_known(None)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_empty_query():
        """Test function when package query returns empty."""
        result = ComponentAnalyses("eco", "pkg", "ver").is_package_known({})
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_missing_data():
        """Test function when package query returns empty."""
        query = dict(result={})
        result = ComponentAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_empty_data():
        """Test function when package query returns empty."""
        query = dict(result=dict(data={}))
        result = ComponentAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is False

    @staticmethod
    def test_is_package_known_with_query_actual_data():
        """Test Function for known package info."""
        query = dict(result=dict(data=["random"]))
        result = ComponentAnalyses("eco", "pkg", "ver").is_package_known(query)
        assert result is True

    @staticmethod
    @patch('bayesian.utility.db_gateway.GraphAnalyses.get_ca_data_from_graph', return_value=None)
    def test_get_vendor_analyses(_graph):
        """Test Function for vendor analyses."""
        analyses = ComponentAnalyses('eco', 'pkg', 'ver').get_component_analyses_response()
        assert analyses is None

    @staticmethod
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.generate_recommendation')
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalyses.is_package_known', return_value=True)
    @patch('bayesian.utility.db_gateway.GraphAnalyses.get_ca_data_from_graph')
    def test_get_vendor_analyses_response_builder(_graph, _known, _recommendation):
        """Test function for vendor analyses response builder."""
        _recommendation.return_value = 'kuchbhi'
        analyses = ComponentAnalyses('eco', 'pkg', 'ver').get_component_analyses_response()
        assert analyses == 'kuchbhi'

    @staticmethod
    @patch('bayesian.utility.db_gateway'
           '.GraphAnalyses.get_ca_data_from_graph', return_value=Exception)
    def test_get_vendor_analyses_response_builder_exception(_graph):
        """Generates exception. Test Exception Block."""
        analyses = ComponentAnalyses('eco', 'pkg', 'ver').get_component_analyses_response()
        assert analyses is None


class ComponentAnalysisResponseBuilderTest(unittest.TestCase):
    """Test Cases for Response Builder."""

    graph_response = dict(result=dict(data=[{}]))

    @classmethod
    def setUpClass(self):
        """Class variables initialised."""
        self.eco = 'pypi'
        self.ver = '1'
        self.pkg = 'pkg'

    def test_generate_recommendation_no_recommendation(self):
        """Test Function for No recommendation."""
        response = ComponentAnalysisResponseBuilder(
            self.eco, self.pkg, self.ver).generate_recommendation(self.graph_response)
        self.assertEqual(response, dict(recommendation={}))

    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.generate_response', return_value={})
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.get_severity')
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.get_vulnerabilities_count')
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.get_version_without_cves')
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.get_cve_maps', return_value=[])
    @patch('bayesian.utility.v2.ca_response_builder'
           '.ComponentAnalysisResponseBuilder.has_cves', return_value=True)
    def test_generate_recommendation_same_version(self, _hascve, _cvemaps, _nocve,
                                                  _vulcount, _severity, _response):
        """Test Function for Generate recommendation_same_version."""
        _vulcount.return_value = (0, 0)
        mocked_response = {'result': {'data': [
            {'version': {'version': ['1']},
             'cve': 'cve',
             'package':{'latest_non_cve_version': ["1.0"]}
             }
        ]}}
        response = ComponentAnalysisResponseBuilder(
            self.eco, self.pkg, self.ver).generate_recommendation(mocked_response)
        self.assertDictEqual(response, {})

    @patch('bayesian.utility.v2.ca_response_builder'
           '.CABatchResponseBuilder.get_link')
    @patch('bayesian.utility.v2.ca_response_builder'
           '.CABatchResponseBuilder.get_exploitable_cves_counter')
    def test_get_premium_response(self, _mock1, _mock2):
        """Test Get Premium Response."""
        _mock1.return_value = 1
        _mock2.return_value = "https://snyk.io/vuln/pypi:django"
        obj = CABatchResponseBuilder(self.eco)
        obj.severity = ["high", "high"]
        obj.package = "django"
        obj.version = "1.1"
        response = obj.get_premium_response()
        ideal_response = {'package': 'django',
                          'version': '1.1',
                          'recommended_versions': '',
                          'package_unknown': False,
                          'vendor_package_link': 'https://snyk.io/vuln/pypi:django',
                          'vulnerability': [],
                          'message': 'django - 1.1 has ',
                          'highest_severity': 'high',
                          'known_security_vulnerability_count': 0,
                          'security_advisory_count': 0,
                          'exploitable_vulnerabilities_count': 1
                          }
        self.assertEqual(response, ideal_response)

    def test_get_premium_message_with_pub_pvt_vul(self):
        """Test Get Premium Message With Public and Private Vulnerabilities."""
        obj = CABatchResponseBuilder(self.eco)
        obj.public_vul = 1
        obj.pvt_vul = 1
        obj.package = "django"
        obj.version = "1.1"
        obj.severity = ['high']
        msg = obj.get_premium_message(1)
        ideal_msg = "django - 1.1 has 1 known security vulnerability " \
                    "and 1 security advisory with 1 exploitable " \
                    "vulnerability and high severity. No recommended version."
        self.assertEqual(msg, ideal_msg)

    def test_get_premium_message_with_pvt_vul(self):
        """Test Get Premium Message With Private Vulnerabilities."""
        obj = CABatchResponseBuilder(self.eco)
        obj.public_vul = 0
        obj.pvt_vul = 1
        obj.package = "django"
        obj.version = "1.1"
        obj.severity = ['high']
        msg = obj.get_premium_message(1)
        ideal_msg = "django - 1.1 has 1 security advisory with 1 exploitable " \
                    "vulnerability and high severity. No recommended version."
        self.assertEqual(msg, ideal_msg)

    def test_get_premium_message_with_public_vul(self):
        """Test Get Premium Message With Public Vulnerabilities."""
        obj = CABatchResponseBuilder(self.eco)
        obj.public_vul = 1
        obj.pvt_vul = 0
        obj.package = "django"
        obj.version = "1.1"
        obj.severity = ['high']
        msg = obj.get_premium_message(1)
        ideal_msg = "django - 1.1 has 1 known security vulnerability with " \
                    "1 exploitable vulnerability and high severity. No recommended version."
        self.assertEqual(msg, ideal_msg)

    def test_get_premium_message_with_0_exploit_vul(self):
        """Test Get Premium Message With Public Vulnerabilities."""
        obj = CABatchResponseBuilder(self.eco)
        obj.public_vul = 1
        obj.pvt_vul = 1
        obj.package = "django"
        obj.version = "1.1"
        obj.severity = ['high']
        msg = obj.get_premium_message(0)
        ideal_msg = "django - 1.1 has 1 known security vulnerability " \
                    "and 1 security advisory with high severity. No recommended version."
        self.assertEqual(msg, ideal_msg)

    def test_get_message_with_pvt_vul_equal_len(self):
        """Test Message with Private Vulnerability equal len of severities and vul count."""
        response_obj = ComponentAnalysisResponseBuilder("pypi", "django", "1.1")
        response_obj.pvt_vul = 1
        response_obj.severity = ['high']
        message = response_obj.get_message()
        ideal_msg = "django - 1.1 has 1 security advisory having high severity. "
        self.assertEqual(message, ideal_msg)

    def test_get_message_with_pvt_vul_unequal_len(self):
        """Test Message with Private Vulnerability unequal len of severities and vul count."""
        response_obj = ComponentAnalysisResponseBuilder("pypi", "django", "1.1")
        response_obj.pvt_vul = 2
        response_obj.severity = ['high']
        message = response_obj.get_message()
        ideal_msg = "django - 1.1 has 2 security advisory with 1 having high severity. "
        self.assertEqual(message, ideal_msg)

    def test_get_message_with_public_vul_equal(self):
        """Test Message with Public Vulnerability equal len of severities and vul count."""
        response_obj = ComponentAnalysisResponseBuilder("pypi", "django", "1.1")
        response_obj.public_vul = 1
        response_obj.nocve_version = "3.1"
        response_obj.severity = ['high']
        message = response_obj.get_message()
        ideal_msg = "django - 1.1 has 1 known security vulnerability " \
                    "having high severity. Recommendation: use version 3.1."
        self.assertEqual(message, ideal_msg)

    def test_get_message_with_public_vul_unequal(self):
        """Test Message with Public Vulnerability unequal len of severities and vul count."""
        response_obj = ComponentAnalysisResponseBuilder("pypi", "django", "1.1")
        response_obj.public_vul = 3
        response_obj.nocve_version = "3.1"
        response_obj.severity = ['high']
        message = response_obj.get_message()
        print("Mesa", message)
        ideal_msg = "django - 1.1 has 3 known security vulnerability with 1 " \
                    "having high severity. Recommendation: use version 3.1."
        self.assertEqual(message, ideal_msg)

    def test_get_message_with_both_vul(self):
        """Test Message with Both Vulnerability."""
        response_obj = ComponentAnalysisResponseBuilder("pypi", "django", "1.1")
        response_obj.public_vul = 1
        response_obj.pvt_vul = 1
        response_obj.severity = ['high']
        message = response_obj.get_message()
        ideal_msg = "django - 1.1 has 1 known security vulnerability and 1 " \
                    "security advisory with 1 having high severity. " \
                    "No recommended version."
        self.assertEqual(message, ideal_msg)

    def test_get_version_without_cves(self):
        """Test Get version without cves."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        version = response_obj.get_version_without_cves(['1.1'])
        self.assertEqual(version, '1.1')

    def test_get_version_without_cves_highest(self):
        """Test Get highest version without cves."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        version = response_obj.get_version_without_cves(['2', '3'])
        self.assertEqual(version, '3')

    @patch('bayesian.utility.v2.ca_response_builder.'
           'ComponentAnalysisResponseBuilder.get_cve_maps')
    @patch('bayesian.utility.v2.ca_response_builder.'
           'ComponentAnalysisResponseBuilder.get_registration_link')
    @patch('bayesian.utility.v2.ca_response_builder.'
           'ComponentAnalysisResponseBuilder.get_message')
    def test_generate_response(self, _mock_msg, _mock_link, _mock_maps):
        """Test Response Generator Function."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)

        _mock_msg.return_value = 'You are Superb.'
        _mock_link.return_value = 'https://xyx.com'
        _mock_maps.return_value = {}

        response_obj.nocve_version = 1
        response_obj.severity = ['high']
        response_obj.public_vul = 2
        response_obj.pvt_vul = 1
        response = response_obj.generate_response()
        mocked_response = dict(
            recommended_versions=response_obj.nocve_version,
            registration_link=_mock_link.return_value,
            component_analyses=dict(vulnerability=_mock_maps.return_value),
            message=_mock_msg.return_value,
            severity=response_obj.severity[0],
            known_security_vulnerability_count=response_obj.public_vul,
            security_advisory_count=response_obj.pvt_vul,
        )
        self.assertDictEqual(response, mocked_response)

    def test_get_vulnerabilities_count_zero_exception(self):
        """Test Vulnerabilities count Exception."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [dict()]
        pub_vul, pvt_vul = response_obj.get_vulnerabilities_count()
        self.assertEquals(pub_vul, 0)
        self.assertEquals(pvt_vul, 0)

    def test_get_vulnerabilities_count_non_zero_pvt(self):
        """Test Vulnerabilities count Private."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [dict(snyk_pvt_vulnerability=[True])]
        pub_vul, pvt_vul = response_obj.get_vulnerabilities_count()
        self.assertEquals(pub_vul, 0)
        self.assertEquals(pvt_vul, 1)

    def test_get_vulnerabilities_count_non_zero_public(self):
        """Test Vulnerabilities count Public."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [dict(snyk_pvt_vulnerability=[False])]
        pub_vul, pvt_vul = response_obj.get_vulnerabilities_count()
        self.assertEquals(pub_vul, 1)
        self.assertEquals(pvt_vul, 0)

    def test_registration_link(self):
        """Test Vulnerabilities count."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        link = response_obj.get_registration_link()
        result = urlparse(link)
        self.assertTrue(all([result.scheme, result.netloc, result.path]), "Invalid Link.")
        self.assertIsInstance(link, str)

    def test_get_link(self):
        """Test link to vendor website."""
        link = ComponentAnalysisResponseBuilder(
            'maven', 'com.fasterxml.jackson.core:jackson-databind', '2.8.9').get_link()
        self.assertEqual(link, "https://snyk.io/vuln/maven:" + quote(
            "com.fasterxml.jackson.core:jackson-databind"))

    def test_get_exploitable_cves_counter_zero(self):
        """Test Exploitable Vulnerabilities counter."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        count = response_obj.get_exploitable_cves_counter()
        self.assertEqual(count, 0)

    def test_get_exploitable_cves_counter_exception(self):
        """Test Exploitable Vulnerabilities counter Exception."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [{"exploit": []}]
        count = response_obj.get_exploitable_cves_counter()
        self.assertEqual(count, None)

    def test_get_exploitable_cves_counter_non_zero(self):
        """Test Exploitable Vulnerabilities counter."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [{"exploit": ["High"]}]
        count = response_obj.get_exploitable_cves_counter()
        self.assertEqual(count, 1)

    def test_get_total_vulnerabilities(self):
        """Test Exploitable Vulnerabilities counter."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        count = response_obj.get_total_vulnerabilities()
        self.assertEqual(count, 0)

    def test_get_severity_exception(self):
        """Test Severity with unknown value, raises exception."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [{'severity': []}]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, [])

    def test_get_severity_return_critical(self):
        """Test Severity Procedure. Severity "critical" has highest precedence."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [
            {'severity': ['medium']},
            {'severity': ['high']},
            {'severity': ['critical']},
            {'severity': ['low']},
            {'severity': ['critical']},
        ]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ['critical', 'critical'])

    def test_get_severity_return_high(self):
        """Test Severity Procedure. Severity "High" has higher precedence."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [
            {'severity': ['medium']},
            {'severity': ['low']},
            {'severity': ['high']},
            {'severity': ['medium']},
            {'severity': ['medium']},
        ]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ['high'])

    def test_get_severity_return_medium(self):
        """Test Severity Procedure. Severity "Medium" has higher precedence."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [
            {'severity': ['low']},
            {'severity': ['medium']},
            {'severity': ['low']},
            {'severity': ['low']},
        ]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ['medium'])

    def test_get_severity_return_low(self):
        """Test Severity Procedure. Severity "low" has higher precedence."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [
            {'severity': ['low']},
            {'severity': ['low']},
        ]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ['low', 'low'])

    def test_get_severity_return_exception(self):
        """Test Severity Procedure. Severity is invalid."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [
            {'severity': ['invalid1']},
            {'severity': ['invalid2']},
        ]

        with pytest.raises(Exception) as exception:
            response_obj.get_severity()
        self.assertIs(exception.type, Exception)

    def test_get_severity_known_values(self):
        """Test Severity with known values, expect to get medium severity."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [{'severity': ["medium", "low"]}]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ["medium"])

    def test_get_severity_known_values_critical(self):
        """Test Severity with known critical value, expect to get critical severity."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = [{'severity': ["critical", "medium", "low", "high"]}]
        severity = response_obj.get_severity()
        self.assertListEqual(severity, ["critical"])

    def test_get_cve_maps_empty(self):
        """Test cve maps with empty cve map, expect empty list []."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        response_obj._cves = []
        cve_maps = response_obj.get_cve_maps()
        self.assertListEqual(cve_maps, [])

    def test_get_cve_maps_non_empty(self):
        """Test cve maps with vulnerability data, expect to get mock data as response."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        vul_data = dict(
            snyk_vuln_id=["SNYK:0101"],
            cvss_scores=["9.0"],
            snyk_pvt_vulnerability=[True],
            snyk_cwes=["CWES-01", "CWES-02"],
            snyk_cvss_v3=["4.5"],
            severity=["medium"],
            title=["Test title for CVE"],
            snyk_url=["https://test.com/cve-01"],
            snyk_cve_ids=["CVE-01", "CVE-02", "CVE-03"],
            fixed_in=[">=0.19.0-beta.1"])
        mocked_response = [dict(
            vendor_cve_ids=vul_data['snyk_vuln_id'][0],
            cvss=vul_data['cvss_scores'][0],
            is_private=vul_data['snyk_pvt_vulnerability'][0],
            cwes=["CWES-01", "CWES-02"],
            cvss_v3="4.5",
            severity="medium",
            title="Test title for CVE",
            url="https://test.com/cve-01",
            cve_ids=["CVE-01", "CVE-02", "CVE-03"],
            fixed_in=[">=0.19.0-beta.1"])
        ]
        response_obj._cves = [vul_data]
        cve_maps = response_obj.get_cve_maps()
        self.assertListEqual(cve_maps, mocked_response)

    def test_get_cve_maps_default(self):
        """Test cve maps with empty value, expect to get respose with default values."""
        response_obj = ComponentAnalysisResponseBuilder(self.eco, self.pkg, self.ver)
        vul_data = dict()
        mocked_response = [dict(
            vendor_cve_ids=None,
            cvss='None',
            is_private=None,
            cwes=[],
            cvss_v3=None,
            severity=None,
            title=None,
            url=None,
            cve_ids=[],
            fixed_in=[])
        ]
        response_obj._cves = [vul_data]
        cve_maps = response_obj.get_cve_maps()
        self.assertListEqual(cve_maps, mocked_response)
