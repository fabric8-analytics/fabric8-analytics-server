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
"""Data model for Stack analyses API v2."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import Field, BaseModel, root_validator, UUID4
from werkzeug.datastructures import FileStorage
from bayesian.utils import resolved_files_exist, get_ecosystem_from_manifest


class HeaderData(BaseModel):  # noqa: D101
    """Header data for stack and component anaylses calls."""

    uuid: Optional[UUID4] = None


class Ecosystem(str, Enum):
    """Supported ecosystem enumerations."""

    maven = 'maven'
    pypi = 'pypi'
    npm = 'npm'


class StackAnalysesPostRequest(BaseModel):
    """Stack anaylses POST request param model."""

    manifest: FileStorage
    file_path: str
    ecosystem: 'Ecosystem'
    show_transitive: Optional[bool] = Field(
        True,
        description='This is required to enable or disable the transitive support',
    )

    class Config:
        """Validation configuration for model."""

        # Override config to allow arbitoary type i.e., FileStorage.
        arbitrary_types_allowed = True

        # Min length of string should be 1 as '/' is a valid path
        min_anystr_length = 1

    @root_validator()
    def check_input_data(cls, values):  # noqa: F841 - Ignore 'cls' not used check
        """Validate input data for ecosystem and manifest file."""
        ecosystem, manifest = values.get('ecosystem'), values.get('manifest')

        if manifest is None:
            raise ValueError('Error processing request. Manifest is missing')

        if not resolved_files_exist(manifest.filename):
            raise ValueError('Error processing request. Manifest is missing its value {} is '
                             'invalid / not supported'.format(manifest.filename))

        ecosystem_from_manifest = get_ecosystem_from_manifest(manifest.filename)
        if ecosystem != ecosystem_from_manifest:
            raise ValueError('Error processing request. Manifest {} and ecosystem {} does '
                             'not match'.format(manifest.filename, ecosystem))

        return values


class Severity(str, Enum):  # noqa: D101
    low = 'low'
    medium = 'medium'
    high = 'high'
    critical = 'critical'


class BasicVulnerabilityFields(BaseModel):  # noqa: D101
    cve_ids: Optional[List[str]] = None
    cvss: float
    cwes: Optional[List[str]] = None
    cvss_v3: str
    severity: 'Severity'
    title: str
    id: str
    url: str


class Exploit(str, Enum):  # noqa: D101
    High = 'High'
    Functional = 'Functional'
    Proof_of_Concept = 'Proof of Concept'
    Unproven = 'Unproven'
    Not_Defined = 'Not Defined'


class Reference(BaseModel):  # noqa: D101
    title: Optional[str] = None
    url: Optional[str] = None


class PremiumVulnerabilityFields(BasicVulnerabilityFields):  # noqa: D101
    malicious: Optional[bool] = True
    patch_exists: Optional[bool] = False
    fixable: Optional[bool] = False
    exploit: Optional['Exploit'] = None
    description: Optional[str] = None
    fixed_in: Optional[List[str]] = None
    references: Optional[List['Reference']] = None


class Package(BaseModel):  # noqa: D101
    name: str
    version: str
    dependencies: Optional[List['Package']] = None


class ComponentConflictLicensesItem(BaseModel):  # noqa: D101
    license1: Optional[str] = None
    license2: Optional[str] = None


class ComponentConflictItem(BaseModel):  # noqa: D101
    package: str
    conflict_licenses: List[ComponentConflictLicensesItem]


class UnknownItem(BaseModel):  # noqa: D101
    package: Optional[str] = None
    license: Optional[str] = None


class UnknownLicenses(BaseModel):  # noqa: D101
    component_conflict: Optional[List['ComponentConflictItem']] = None
    unknown: Optional[List['UnknownItem']] = None


class ConflictPackages(BaseModel):  # noqa: D101
    package1: str
    license1: str
    package2: str
    license2: str


class LicenseAnalysisStatus(str, Enum):  # noqa: D101
    ComponentConflict = 'ComponentConflict'
    StackConflict = 'StackConflict'
    Successful = 'Successful'
    Unknown = 'Unknown'
    Failure = 'Failure'


class LicenseAnalysis(BaseModel):  # noqa: D101
    reason: Optional[str] = None
    status: Optional[LicenseAnalysisStatus] = None
    recommended_licenses: Optional[List[str]] = None
    outlier_packages: List[Dict[str, Any]] = None
    conflict_packages: List['ConflictPackages'] = None
    current_stack_license: Dict[str, Any] = None
    unknown_licenses: 'UnknownLicenses' = None
    distinct_licenses: Optional[List[str]] = None


class UsedByItem(BaseModel):  # noqa: D101
    name: Optional[str] = None
    stars: Optional[str] = None


class GitHubDetails(BaseModel):  # noqa: D101
    watchers: Optional[str] = None
    first_release_date: Optional[str] = None
    total_releases: Optional[str] = None
    issues: Optional[Dict[str, Any]] = None
    pull_requests: Optional[Dict[str, Any]] = None
    dependent_repos: Optional[str] = None
    open_issues_count: Optional[str] = None
    latest_release_duration: Optional[str] = None
    forks_count: Optional[str] = None
    contributors: Optional[str] = None
    size: Optional[str] = None
    stargazers_count: Optional[str] = None
    used_by: Optional[List[UsedByItem]] = None
    dependent_projects: Optional[str] = None


class PackageDetails(Package):  # noqa: D101
    latest_version: str
    github: Optional['GitHubDetails'] = None
    licenses: Optional[List[str]] = None
    ecosystem: 'Ecosystem'
    url: Optional[str] = None


class PackageDetailsForRegisteredUser(PackageDetails):  # noqa: D101
    public_vulnerabilities: Optional[List['PremiumVulnerabilityFields']] = Field(
        None, description='Publicly known vulnerability details'
    )
    private_vulnerabilities: Optional[List['PremiumVulnerabilityFields']] = Field(
        None,
        description='Private vulnerability details, available only to registered\nusers\n',
    )
    recommended_version: Optional[str] = Field(
        None,
        description=('Recommended package version which includes '
                     'fix for both public and private vulnerabilities.\n'),
    )
    vulnerable_dependencies: Optional[List['PackageDetailsForRegisteredUser']] = Field(
        None, description='List of dependencies which are vulnerable.\n'
    )


class PackageDetailsForFreeTier(PackageDetails):  # noqa: D101
    public_vulnerabilities: Optional[List['BasicVulnerabilityFields']] = Field(
        None, description='Publicly known vulnerability details'
    )
    private_vulnerabilities: Optional[List['BasicVulnerabilityFields']] = Field(
        None, description='Private vulnerability details with limited info'
    )
    recommended_version: Optional[str] = Field(
        None,
        description='Recommended package version which includes fix for public vulnerabilities.\n',
    )
    vulnerable_dependencies: Optional[List['PackageDetailsForFreeTier']] = Field(
        None, description='List of dependencies which are vulnerable.\n'
    )


class StackAnalysesResult(BaseModel):  # noqa: D101
    version: str
    started_at: str
    ended_at: str
    recommendation: 'StackRecommendation'
    uuid: Optional[str] = None
    external_request_id: Optional[str] = None
    registration_status: Optional[str] = None
    manifest_file_path: Optional[str] = None
    manifest_name: Optional[str] = None
    ecosystem: Optional['Ecosystem'] = None
    unknown_dependencies: Optional[List['Package']] = None
    license_analysis: Optional['LicenseAnalysis'] = None


class StackAnalysesResultForRegisteredUser(StackAnalysesResult):  # noqa: D101
    analyzed_dependencies: Optional[List['PackageDetailsForRegisteredUser']] = Field(
        None,
        description="All direct dependencies details regardless of it's vulnerability status\n",
    )


class StackAnalysesResultForFreeTier(StackAnalysesResult):  # noqa: D101
    registration_link: str
    analyzed_dependencies: Optional[List['PackageDetailsForFreeTier']] = Field(
        None,
        description="All direct dependencies details regardless of it's vulnerability status\n",
    )


class RecommendedPackageData(PackageDetails):  # noqa: D101
    cooccurrence_probability: Optional[float] = 0
    cooccurrence_count: int = 0
    topic_list: Optional[List[str]] = None


class StackRecommendation(BaseModel):  # noqa: D101
    manifest_file_path: str = None
    companion: List['RecommendedPackageData']
    usage_outliers: List[Dict[str, Any]]


Package.update_forward_refs()
PackageDetailsForRegisteredUser.update_forward_refs()
PackageDetailsForFreeTier.update_forward_refs()
StackAnalysesResultForRegisteredUser.update_forward_refs()
StackAnalysesResultForFreeTier.update_forward_refs()
RecommendedPackageData.update_forward_refs()
