"""Tests for functions and classes implemented in 'utils' module."""

import datetime
import pytest
import semantic_version as sv
from bayesian.utils import (
    is_valid, get_user_email,
    convert_version_to_proper_semantic as cvs,
    version_info_tuple as vt,
    resolved_files_exist,
    get_ecosystem_from_manifest,
    check_for_accepted_ecosystem
)
from f8a_worker.enums import EcosystemBackend
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult
from urllib.request import urlopen

now = datetime.datetime.now()
later = now + datetime.timedelta(minutes=10)

mocker_input_cve = {
    "result": {
        "data": [
            {
                "cve_id": [
                    "CVE-2019-0542"
                ],
                "cecosystem": [
                    "npm"
                ],
                "cvss_v2": [
                    7.5
                ],
                "nvd_status": [
                    "ANALYZED"
                ],
                "vertex_label": [
                    "CVE"
                ],
                "fixed_in": [
                    "<=3.8.1,3.8.1",
                    "<=3.9.2,3.9.2",
                    ">=3.10.1"
                ],
                "description": [
                    "A remote code execution vulnerability"
                ],
                "modified_date": [
                    "20190509"
                ]
            },
            {
                "cve_id": [
                    "CVE-2019-10742"
                ],
                "cecosystem": [
                    "npm"
                ],
                "cvss_v2": [
                    5
                ],
                "nvd_status": [
                    "ANALYZED"
                ],
                "vertex_label": [
                    "CVE"
                ],
                "fixed_in": [
                    ">=0.19.0-beta.1"
                ],
                "description": [
                    "Axios up to and including 0.18.0 allows attackers to cause a denial of service"
                ],
                "modified_date": [
                    "20190509"
                ]
            }
        ],
        "meta": {}
    }
}

mocker_input_epv = {
    "result": {
        "data": [
            {
                "licenses": [
                    "MIT License"
                ],
                "last_updated": [
                    1557381635.7018023
                ],
                "declared_licenses": [
                    "MIT"
                ],
                "pecosystem": [
                    "npm"
                ],
                "pname": [
                    "xterm"
                ],
                "vertex_label": [
                    "Version"
                ],
                "description": [
                    "Full xterm terminal in your browser"
                ],
                "version": [
                    "2.9.2"
                ]
            },
            {
                "last_updated": [
                    1557381637.6013052
                ],
                "declared_licenses": [
                    "MIT"
                ],
                "pecosystem": [
                    "npm"
                ],
                "pname": [
                    "xterm"
                ],
                "vertex_label": [
                    "Version"
                ],
                "description": [
                    "Full xterm terminal in your browser"
                ],
                "version": [
                    "3.0.1"
                ]
            }
        ],
        "meta": {}
    }
}

non_cve_input = {
    "result": {
        "data": [
            {
                "cve": {
                    "ecosystem": ["npm"],
                    "cve_id": ["CVE-2018-0001"],
                    "cvss_v2": [10.0],
                    "nvd_status": ["Awaiting Analyses"],
                    "description": ["Some description here updated just now."],
                    "modified_date": ["20180911"]
                },
                "version": {
                    "pname": ["lodash"],
                    "version": ["4.17.4"],
                    "pecosystem": ["npm"]
                },
                "package": {
                    "name": ["lodash"],
                    "latest_non_cve_version": ["4.17.11"],
                    "pecosystem": ["npm"]
                }
            }
        ]
    }
}


@pytest.fixture
def analyses(app):
    """Prepare the known set of data used by tests."""
    e1 = Ecosystem(name='npm', backend=EcosystemBackend.npm)
    p1 = Package(ecosystem=e1, name='arrify')
    v1 = Version(package=p1, identifier='1.0.1')
    model1 = Analysis(version=v1, started_at=now, finished_at=later)
    app.rdb.session.add(model1)

    e2 = Ecosystem(name='pypi', backend=EcosystemBackend.pypi)
    p2 = Package(ecosystem=e2, name='flexmock')
    v2 = Version(package=p2, identifier='0.10.1')
    model2 = Analysis(version=v2, started_at=later, access_count=1)
    app.rdb.session.add(model2)
    app.rdb.session.commit()

    worker_results2 = {'a': 'b', 'c': 'd', 'e': 'f', 'g': 'h', 'i': 'j',
                       'digests': {'details':
                                   [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}
    for w, tr in worker_results2.items():
        app.rdb.session.add(WorkerResult(analysis_id=model2.id, worker=w, task_result=tr))

    model3 = Analysis(version=v2, started_at=later, access_count=1,
                      audit={'audit': {'audit': 'audit', 'e': 'f', 'g': 'h'}, 'a': 'b', 'c': 'd'})
    app.rdb.session.add(model3)
    app.rdb.session.commit()
    worker_results3 = {'digests': {'details':
                                   [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}
    for w, tr in worker_results3.items():
        app.rdb.session.add(WorkerResult(analysis_id=model3.id, worker=w, task_result=tr))
    app.rdb.session.commit()
    return (model1, model2, model3)


class TestFetchFileFromGithub:
    """Tests for the function 'fetch_file_from_github' implemented in 'utils' module."""

    __url = 'https://github.com/ravsa/testManifest'

    def test_github_url_exist_or_not(self):
        """Check for github repo exist or not."""
        assert urlopen(
            self.__url).code == 200, "Not able to access the url {}".format(self.__url)


def test_semantic_versioning():
    """Check the function cvs()."""
    package_name = "test_package"
    version = "-1"
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = ""
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = None
    assert cvs(version, package_name) == sv.Version("0.0.0")
    version = "1.5.2.RELEASE"
    assert cvs(version, package_name) == sv.Version("1.5.2+RELEASE")
    version = "1.5-2.RELEASE"
    assert cvs(version, package_name) == sv.Version("1.5.2+RELEASE")
    version = "2"
    assert cvs(version, package_name) == sv.Version("2.0.0")
    version = "2.3"
    assert cvs(version, package_name) == sv.Version("2.3.0")
    version = "2.0.rc1"
    assert cvs(version, package_name) == sv.Version("2.0.0+rc1")


def test_version_info_tuple():
    """Check the function vt()."""
    version_str = "2.0.rc1"
    package_name = "test_package"
    version_obj = cvs(version_str, package_name)
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == version_obj.major
    assert version_info[1] == version_obj.minor
    assert version_info[2] == version_obj.patch
    assert version_info[3] == version_obj.build


def test_version_info_tuple_empty_version_obj():
    """Check the function vt() for empty version object."""
    version_obj = ""
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == 0
    assert version_info[1] == 0
    assert version_info[2] == 0
    assert version_info[3] == tuple()


def test_get_user_email():
    """Check the function get_user_email()."""
    assert get_user_email(None) == 'bayesian@redhat.com'

    user_profile = {'email': 'xyzzy'}
    assert get_user_email(user_profile) == 'xyzzy'

    user_profile = {'not-email': 'xyzzy'}
    assert get_user_email(user_profile) == 'bayesian@redhat.com'


def test_is_valid():
    """Check the function is_valid()."""
    assert not is_valid(None)
    assert is_valid("parameter")


def test_check_manifest_for_resolved_deps():
    """Test test_check_manifest_for_resolved_deps function."""
    manifests = [
        {
            'filename': "npmlist.json",
            'ecosystem': "npm"
        },
        {
            'filename': "npm-abcd.json",
            'ecosystem': "npm"
        }
    ]
    resp = resolved_files_exist(manifests)
    assert resp is True

    manifests = [
        {
            'filename': "npm-list.json",
            'ecosystem': "npm"
        },
        {
            'filename': "npm-abcd.json",
            'ecosystem': "npm"
        }
    ]
    resp = resolved_files_exist(manifests)
    assert resp is False

    resp = resolved_files_exist("dependencies.txt")
    assert resp is True


def test_get_ecosystem_from_manifest():
    """Test get_ecosystem_from_manifest function."""
    manifests = [
        {
            'filename': "npmlist.json",
            'ecosystem': "npm"
        },
        {
            'filename': "npm-abcd.json",
            'ecosystem': "npm"
        }
    ]
    resp = get_ecosystem_from_manifest(manifests)
    assert resp == "npm"

    manifests = [
        {
            'filename': "dependencies.txt",
            'ecosystem': "maven"
        }
    ]
    resp = get_ecosystem_from_manifest(manifests)
    assert resp == "maven"

    resp = get_ecosystem_from_manifest("dependencies.txt")
    assert resp == "maven"

    resp = get_ecosystem_from_manifest("npm-abcd.txt")
    assert resp is None


def test_check_for_accepted_ecosystem():
    """Test check_for_accepted_ecosystem function."""
    resp = check_for_accepted_ecosystem("maven")
    assert resp

    resp = check_for_accepted_ecosystem("abcd")
    assert not resp
