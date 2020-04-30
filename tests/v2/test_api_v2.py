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

"""Unit tests for the REST API V2 module."""

import io
import datetime
import pytest
from pathlib import Path

from f8a_worker.enums import EcosystemBackend
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult


# Build api URL based on route
def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v2' + route


# Asset if link does not match expected value
def assert_pages(response, p=None, n=None):
    """Check the 'paginated' output."""
    # TODO can not find any usage of this function
    pgs = []
    if p:
        pgs.append({'url': p, 'rel': 'prev'})
    if n:
        pgs.append({'url': n, 'rel': 'next'})
    link = response.headers['Link']
    expected = ', '.join(['<{url}>; rel="{rel}"'.format(**d) for d in pgs])
    assert link == expected


# Example partial analyses for testing purposes
now = datetime.datetime.now()
later = now + datetime.timedelta(minutes=10)
even_later = now + datetime.timedelta(minutes=10)


@pytest.fixture
def fill_analyses(app):
    """Prepare static data used by unit tests."""
    # TODO can not find any usage of this function
    ecosystems = [
        Ecosystem(name='pypi', backend=EcosystemBackend.pypi, url='https://pypi.python.org/',
                  fetch_url='https://pypi.python.org/pypi'),
        Ecosystem(name='npm', backend=EcosystemBackend.npm, url='https://www.npmjs.com/',
                  fetch_url='https://registry.npmjs.org/'),
        Ecosystem(name='go', backend=EcosystemBackend.scm),
    ]

    packages = [
        Package(name='flexmock', ecosystem=ecosystems[0]),
        Package(name='requests', ecosystem=ecosystems[0]),
        Package(name='sequence', ecosystem=ecosystems[1]),
        Package(name='arrify', ecosystem=ecosystems[1]),
        Package(name='serve-static', ecosystem=ecosystems[1]),
    ]

    versions = [
        Version(identifier='0.10.1', package=packages[0]),
        Version(identifier='0.9.1', package=packages[0]),
        Version(identifier='2.0.0', package=packages[1]),
        Version(identifier='2.2.1', package=packages[2]),
        Version(identifier='1.0.1', package=packages[3]),
        Version(identifier='1.7.1', package=packages[4]),
    ]

    analyses = [
        Analysis(version=versions[0], started_at=now),                     # pypi/flexmock/0.10.1
        Analysis(version=versions[0], started_at=later, access_count=1),   # pypi/flexmock/0.10.1
        Analysis(version=versions[1], started_at=even_later),              # pypi/flexmock/0.9.1
        Analysis(version=versions[2], started_at=now),                     # pypi/requests/2.0.0
        Analysis(version=versions[3], started_at=later),                   # npm/sequence/2.2.1
        Analysis(version=versions[4], started_at=now, finished_at=later),  # npm/arrify/1.0.1
        Analysis(version=versions[5], started_at=now, finished_at=later,
                 release='npm:serve-static:1.7.1'),                      # npm/serve-static/1.7.1
    ]
    # worker results that correspond to analyses above
    worker_results = [
        WorkerResult(worker='digests', analysis=analyses[1],
                     task_result={'details': [{'artifact': True,
                                               'sha1':
                                               '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}),
        WorkerResult(worker='static_analysis', task_result={'details': []}, analysis=analyses[1]),
        WorkerResult(worker='source_licenses',
                     task_result={'schema': {'name': 'source_licenses', 'version': '1-0-0'}},
                     analysis=analyses[1])
    ]

    # TODO: just a placeholder, it won't work in real tests!!!
    package_gh_usage = None

    for a in ecosystems + packages + versions + analyses + worker_results + package_gh_usage:
        app.rdb.session.add(a)
        app.rdb.session.commit()

    return (ecosystems, packages, versions, analyses, worker_results, package_gh_usage)


@pytest.fixture
def fill_packages_for_paging(app, request):
    """Create and store set of packages used by unit tests."""
    assert request
    e = Ecosystem(name='pypi', backend=EcosystemBackend.pypi)
    app.rdb.session.add(e)
    for p in range(0, 11):
        app.rdb.session.add(Package(ecosystem=e, name=str(p)))

    app.rdb.session.commit()
    # no cleanup (we're recreating DB after every test case)


@pytest.mark.usefixtures('client_class')
class TestApiV2Root(object):
    """Basic tests if all endpoints are accessible."""

    api_root = {
        "paths": [
            "/api/v2",
            "/api/v2/component-analyses/<ecosystem>/<package>/<version>",
            "/api/v2/stack-analyses",
            "/api/v2/stack-analyses/<external_request_id>",
            "/api/v2/system/version"
        ]
    }

    def test_api_root(self, accept_json):
        """Basic tests if all endpoints are accessible."""
        res = self.client.get(api_route_for('/'), headers=accept_json)
        assert res.status_code == 200
        assert res.json == self.api_root


@pytest.mark.usefixtures('client_class')
class TestCommonEndpoints(object):
    """Basic tests for several endpoints."""

    def test_readiness(self, accept_json):
        """Test the /readiness endpoint."""
        res = self.client.get(api_route_for('/readiness'), headers=accept_json)
        assert res.status_code == 200

    @pytest.mark.usefixtures('rdb')
    def test_liveness(self, accept_json):
        """Test the /liveness endpoint."""
        res = self.client.get(api_route_for('/liveness'), headers=accept_json)
        assert res.status_code == 200 or res.status_code == 500

    def test_error(self, accept_json):
        """Test the /_error endpoint."""
        res = self.client.get(api_route_for('/_error'), headers=accept_json)
        assert res.status_code == 404

    def test_system_version(self, accept_json):
        """Test the /system/version endpoint."""
        res = self.client.get(api_route_for('/system/version'), headers=accept_json)
        assert res.status_code == 200

    def test_component_analyses(self, accept_json):
        """Test the /component-analyses endpoint for GET."""
        res = self.client.get(api_route_for('/component-analyses/abb/cc/dd'),
                              headers=accept_json)
        assert res.status_code == 400


@pytest.mark.usefixtures('client_class')
class TestStackAnalysesEndpoints(object):
    """Tests for /stack_analyses endpoints."""

    def test_sa_invalid_get_request(self, accept_json):
        """Test invalid get request using wrong enpdoint."""
        res = self.client.get(api_route_for('/stack-analyses'), headers=accept_json)
        assert res.status_code == 404

    def test_sa_invalid_post_request(self, accept_json):
        """Test invalid post request using wrong endpoint."""
        res = self.client.post(api_route_for('/stack-analyses/invalid_id'), headers=accept_json)
        assert res.status_code == 404

    def test_sa_get_with_invalid_id(self, accept_json):
        """Test get endpoint with invalid request id."""
        res = self.client.get(api_route_for('/stack-analyses/invalid_id'), headers=accept_json)
        assert res.status_code == 404

    def test_sa_post_missing_all_params(self, accept_json):
        """Test post endpoint without and params."""
        res = self.client.post(api_route_for('/stack-analyses'), headers=accept_json)

        # Expecting authentication error [400]
        assert res.status_code == 400

    def test_sa_post_missing_manifest_params(self, accept_json):
        """Test post request without menifest param."""
        data = {
            "file_path": "/tmp/bin",
            "ecosystem": "pypi"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting  missing manifest error
        assert res.status_code == 400

    def test_sa_post_missing_file_path_params(self, accept_json):
        """Test post request without file_path param."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "ecosystem": "npm"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting  missing file_path error
        assert res.status_code == 400

    def test_sa_post_missing_ecosystem_params(self, accept_json):
        """Test post request without ecosystem param."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting  missing ecosystem error
        assert res.status_code == 400

    def test_sa_post_invalid_ecosystem_params(self, accept_json):
        """Test post request with invalid ecosystem value in param."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin",
            "ecosystem": ".net_ecosystem"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting  invalid ecosystem error
        assert res.status_code == 400

    def test_sa_post_valid_request_202(self, accept_json):
        """Test post with a valid params, just ensuring 202 response."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin",
            "ecosystem": "npm"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        assert res.status_code == 200

        # Ensure 202 upon immediate get query.
        stack_id = res.json['id']
        res = self.client.get(api_route_for('/stack-analyses/') + stack_id,
                              headers=headers)
        assert res.status_code == 202

    def test_sa_post_valid_request_400(self, accept_json):
        """Test post with invalid manifest file content."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/400/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin",
            "ecosystem": "npm"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting exception due to invalid maniest file content
        assert res.status_code == 400

    def test_sa_post_request_with_mapped_ecosystem(self, accept_json):
        """Test post with correct ecosystem that need to be mapped to support ecosystem."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin",
            "ecosystem": "node"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )

        assert res.status_code == 200

        # Ensure 202 upon immediate get query.
        stack_id = res.json['id']
        res = self.client.get(api_route_for('/stack-analyses/') + stack_id, headers=headers)
        assert res.status_code == 202


'''
Enable this test case once we have backbone server also to serve the request.
add this imports ::
import os
import time

    def test_sa_post_valid_request_200(self, accept_json):
        """Test post call and verify the positive response with 200."""
        data = {
            "manifest": (io.StringIO(str(Path(__file__).parent /
                                         "data/manifests/202/npmlist.json")).read(),
                         "npmlist.json"),
            "file_path": "/tmp/bin",
            "ecosystem": "npm"
        }

        headers = {
            "x-3scale-account-secret": "not-set"
        }

        res = self.client.post(api_route_for('/stack-analyses'),
                               data=data,
                               content_type='multipart/form-data',
                               headers=headers,
                               )
        # Expecting  invalid ecosystem error
        assert res.status_code == 200
        stack_id = res.json['id']

        # Wait in loop till max timeout.
        exit_timestamp = datetime.datetime.now().timestamp()
        exit_timestamp += os.getenv('STACK_ANALYSIS_REQUEST_TIMEOUT', 120)
        get_status_code = 0
        while get_status_code != 200 and exit_timestamp > datetime.datetime.now().timestamp():
            # Wait for 5 seconds
            time.sleep(5)
            res = self.client.get(api_route_for('/stack-analyses/') + stack_id, headers=headers)
            get_status_code = res.status_code
            print("time: {} stat: {}".format(datetime.datetime.now().timestamp(), get_status_code))

        assert get_status_code == 200
'''


@pytest.mark.usefixtures('client_class')
class TestApiV2SystemVersion(object):
    """Tests for the /api/v2/system/version endpoint."""

    def test_get_system_version(self, accept_json):
        """Test for the /api/v2/system/version endpoint."""
        res = self.client.get(api_route_for('/system/version/'), headers=accept_json)
        assert res.status_code == 200
        assert set(res.json.keys()) == {'committed_at', 'commit_hash'}
