"""Tests for functions and classes implemented in 'utils' module."""

import datetime
import pytest
import semantic_version as sv
import tempfile
import os

from bayesian.utils import (
    get_core_dependencies,
    do_projection,
    fetch_file_from_github,
    is_valid, has_field, get_user_email,
    convert_version_to_proper_semantic as cvs,
    version_info_tuple as vt,
    select_latest_version as slv,
    create_directory_structure as cds)
from f8a_worker.enums import EcosystemBackend
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult
from urllib.request import urlopen

now = datetime.datetime.now()
later = now + datetime.timedelta(minutes=10)


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


@pytest.mark.usefixtures('rdb')
class TestDoProjection(object):
    """Tests for the function 'do_projection' implemented in 'utils' module."""

    def test_empty_projection(self, analyses):
        """Test that no fields are returned for empty projection."""
        projection = []
        expected = {}
        result = do_projection(projection, analyses[0])
        assert expected == result

    def test_simple_projection(self, analyses):
        """Test simple projection of 2 simple arguments."""
        projection = ['ecosystem', 'package']
        # pypi has order 1
        expected = {'ecosystem': 'npm', 'package': 'arrify'}
        returned = do_projection(projection, analyses[0])
        assert expected == returned

    def test_none_projection(self, analyses):
        """Check that original model is returned if projection is None."""
        projection = None
        returned = do_projection(projection, analyses[0])
        expected = analyses[0].to_dict()
        assert expected == returned

    def test_nested_projection(self, analyses):
        """Test whether filtering of nested JSON returns just desired field."""
        projection = ['analyses.digests']
        expected = {'analyses': {'digests': {'details':
                                             [{'artifact': True, 'sha1':
                                               '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}}
        result = do_projection(projection, analyses[1])
        assert expected == result

    def test_combined_projection(self, analyses):
        """Combining simple fields with nested fields."""
        projection = ['analyses.digests', 'analyses.a', 'package']
        expected = {'analyses': {'a': 'b', 'digests': {
            'details': [{'artifact': True, 'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}},
                    'package': 'flexmock'}
        result = do_projection(projection, analyses[1])
        assert expected == result

    def test_three_level_fields(self, analyses):
        """Testing third level of nested JSON."""
        projection = ['analyses.digests.details', 'audit.audit.audit']
        expected = {'audit': {'audit': {'audit': 'audit'}},
                    'analyses':
                    {'digests': {'details':
                                 [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}}
        result = do_projection(projection, analyses[2])
        assert expected == result


class TestFetchFileFromGithub:
    """Tests for the function 'fetch_file_from_github' implemented in 'utils' module."""

    __url = 'https://github.com/ravsa/testManifest'

    def test_github_url_exist_or_not(self):
        """Check for github repo exist or not."""
        assert urlopen(
            self.__url).code == 200, "Not able to access the url {}".format(self.__url)

    def test_repo_with_file_exist(self):
        """Check wheather file exist in github repo."""
        file_name = 'pom.xml'
        result = fetch_file_from_github(self.__url, file_name)
        assert not bool(
            {'filename', 'filepath', 'content'}.symmetric_difference(result[0].keys()))

    def test_repo_file_in_diff_branch(self):
        """Check for file exist in specific branch or not."""
        file_name = 'pom.xml'
        branch_name = 'dev-test-branch'
        result = fetch_file_from_github(
            self.__url, file_name, branch=branch_name)
        assert not bool(
            {'filename', 'filepath', 'content'}.symmetric_difference(result[0].keys()))


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
    # TODO: reduce cyclomatic complexity
    version_str = "2.0.rc1"
    package_name = "test_package"
    version_obj = cvs(version_str, package_name)
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == version_obj.major
    assert version_info[1] == version_obj.minor
    assert version_info[2] == version_obj.patch
    assert version_info[3] == version_obj.build
    version_obj = ""
    version_info = vt(version_obj)
    assert len(version_info) == 4
    assert version_info[0] == 0
    assert version_info[1] == 0
    assert version_info[2] == 0
    assert version_info[3] == tuple()


def test_select_latest_version():
    """Check fucntion slv()."""
    latest = "1.2.2"
    libio = "1.2.3"
    package_name = "test_package"
    result_version = slv(latest, libio, package_name)
    assert result_version == libio
    latest = ""
    libio = ""
    result_version = slv(latest, libio, package_name)
    assert result_version == ""


def test_get_user_email():
    """Check the function get_user_email()."""
    assert get_user_email(None) == 'bayesian@redhat.com'

    user_profile = {'email': 'xyzzy'}
    assert get_user_email(user_profile) == 'xyzzy'

    user_profile = {'not-email': 'xyzzy'}
    assert get_user_email(user_profile) == 'bayesian@redhat.com'


def test_has_field():
    """Check the function has_field()."""
    assert has_field({}, [])
    assert not has_field({}, ["field1", "field2"])
    assert has_field({"field1": 42}, ["field1"])
    assert has_field({"field1": {"field2": 42}}, ["field1", "field2"])


def test_is_valid():
    """Check the function is_valid()."""
    assert not is_valid(None)
    assert is_valid("parameter")


def test_get_core_dependencies():
    """Check the function get_core_dependencies()."""
    assert any(get_core_dependencies('spring-boot'))
    assert get_core_dependencies('xyz') == []


def test_create_dir_structure():
    """Check for directory structure.

    parentdir
    ├── childdir
    └── hello.txt
    """
    dir_struct = {
        'name': 'parentdir',
        'type': 'dir',
        'contains': [
            {
                'name': 'hello.txt',
                'type': 'file',
                'contains': "Some dummy text"
            },
            {
                'name': 'childdir',
                'type': 'dir',
            }
        ]}

    tempdir = tempfile.TemporaryDirectory()
    root_path = tempdir.name
    assert os.path.exists(root_path)

    assert not os.path.exists(os.path.join(root_path, 'parentdir'))
    assert not os.path.exists(os.path.join(root_path, 'parentdir', 'childdir'))
    assert not os.path.isfile(os.path.join(root_path, 'parentdir', 'hello.txt'))

    cds(root_path, dir_struct)

    assert os.path.exists(os.path.join(root_path, 'parentdir'))
    assert os.path.exists(os.path.join(root_path, 'parentdir', 'childdir'))
    assert os.path.isfile(os.path.join(root_path, 'parentdir', 'hello.txt'))
