"""Unit tests for the REST API module."""

import datetime
import json
import os
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from flask import current_app, url_for
from flask_security import current_user, AnonymousUser
import flexmock
from freezegun import freeze_time
import pytest
import requests
import jsonschema

from bayesian import api_v1
from bayesian.schemas import load_all_server_schemas
from f8a_worker.enums import EcosystemBackend
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult
from f8a_worker.schemas import load_all_worker_schemas


def api_route_for(route):
    """Construct an URL to the endpoint for given route."""
    return '/api/v1' + route


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
    for a in ecosystems + packages + versions + analyses + worker_results + package_gh_usage:
        app.rdb.session.add(a)
        app.rdb.session.commit()

    return (ecosystems, packages, versions, analyses, worker_results, package_gh_usage)


@pytest.fixture
def fill_packages_for_paging(app, request):
    """Create and store set of packages used by unit tests."""
    e = Ecosystem(name='pypi', backend=EcosystemBackend.pypi)
    app.rdb.session.add(e)
    for p in range(0, 11):
        app.rdb.session.add(Package(ecosystem=e, name=str(p)))

    app.rdb.session.commit()
    # no cleanup (we're recreating DB after every test case)


@pytest.mark.usefixtures('client_class')
class TestApiV1Root(object):
    """Basic tests if all endpoints are accessible."""

    api_root = {
        "paths": [
            "/api/v1",
            "/api/v1/categories/<runtime>",
            "/api/v1/component-analyses/<ecosystem>/<package>/<version>",
            "/api/v1/component-search/<package>",
            "/api/v1/depeditor-analyses",
            "/api/v1/depeditor-cve-analyses",
            "/api/v1/generate-file",
            "/api/v1/get-next-component/<ecosystem>",
            "/api/v1/master-tags/<ecosystem>",
            "/api/v1/schemas",
            "/api/v1/schemas/<collection>",
            "/api/v1/schemas/<collection>/<name>",
            "/api/v1/schemas/<collection>/<name>/<version>",
            "/api/v1/set-tags",
            "/api/v1/stack-analyses",
            "/api/v1/stack-analyses/<external_request_id>",
            "/api/v1/submit-feedback",
            "/api/v1/system/version",
            "/api/v1/user-feedback",
            "/api/v1/user-intent",
            "/api/v1/user-intent/<user>/<ecosystem>",
            "/api/v1/get-core-dependencies/<runtime>"
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

    def test_stack_analyses(self, accept_json):
        """Test the /stack-analyses endpoint for GET."""
        res = self.client.get(api_route_for('/stack-analyses'), headers=accept_json)
        assert res.status_code == 400 or res.status_code == 401

    def test_component_search(self, accept_json):
        """Test the /component-search endpoint for GET."""
        res = self.client.get(api_route_for('/component-search'), headers=accept_json)
        assert res.status_code == 202 or res.status_code == 401 or res.status_code == 404


@pytest.mark.usefixtures('client_class', 'rdb')
class TestUser(object):
    """Tests for /api/v1/user* endpoints."""

    pass  # TODO


@pytest.mark.usefixtures('client_class')
class TestApiV1SystemVersion(object):
    """Tests for the /api/v1/system/version endpoint."""

    def test_get_system_version(self, accept_json):
        """Test for the /api/v1/system/version endpoint."""
        res = self.client.get(api_route_for('/system/version/'), headers=accept_json)
        assert res.status_code == 200
        assert set(res.json.keys()) == {'committed_at', 'commit_hash'}


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Schemas(object):
    """Tests for the /api/v1/schemas endpoints."""

    def _check_schema_id(self, received_schema, expected_path):
        """Check schema ID added by the API server."""
        expected_id = 'http://localhost' + expected_path + '/'
        assert received_schema['id'] == expected_id

    def test_get_all_schemas(self, accept_json):
        """Test for the /api/v1/schemas endpoint."""
        query_path = api_route_for('/schemas')
        res = self.client.get(query_path, headers=accept_json)
        assert res.status_code == 200
        received_data = res.json
        assert received_data == api_v1.PublishedSchemas.schema_collections
        for collection, schemas in received_data.items():
            collection_path = query_path + "/" + collection
            for name, versions in schemas.items():
                schema_path = collection_path + "/" + name
                for version, schema in versions.items():
                    version_path = schema_path + "/" + version
                    self._check_schema_id(schema, version_path)

    def test_get_schemas_by_collection(self, accept_json):
        """Test for the /api/v1/schemas/api endpoint."""
        collection_path = api_route_for('/schemas/api')
        res = self.client.get(collection_path, headers=accept_json)
        assert res.status_code == 200
        received_data = res.json
        assert received_data == api_v1.PublishedSchemas.\
            schema_collections[api_v1.PublishedSchemas.API_COLLECTION]
        for name, versions in received_data.items():
            schema_path = collection_path + "/" + name
            for version, schema in versions.items():
                version_path = schema_path + "/" + version
                self._check_schema_id(schema, version_path)

        res = self.client.get(api_route_for('/schemas/blahblahblah'), headers=accept_json)
        assert res.status_code == 404

    def test_get_schemas_by_collection_and_name(self, accept_json):
        """Test for the /api/v1/schemas/api/component_analyses endpoint."""
        schema_path = api_route_for('/schemas/api/component_analyses')
        res = self.client.get(schema_path, headers=accept_json)
        assert res.status_code == 200
        received_data = res.json
        assert received_data == api_v1.PublishedSchemas.\
            schema_collections[api_v1.PublishedSchemas.API_COLLECTION]['component_analyses']
        for version, schema in received_data.items():
            version_path = schema_path + "/" + version
            self._check_schema_id(schema, version_path)

        res = self.client.get(api_route_for('/schemas/api/blahblahblah'),
                              headers=accept_json)
        assert res.status_code == 404

    def test_get_schema_by_collection_and_name_and_version(self, accept_json):
        """Test for the /api/v1/schemas/api/component_analyses endpoint."""
        version_path = api_route_for('/schemas/api/component_analyses/1-0-0')
        res = self.client.get(version_path, headers=accept_json)
        assert res.status_code == 200
        received_data = res.json
        assert received_data == api_v1.PublishedSchemas.\
            schema_collections[api_v1.PublishedSchemas.
                               API_COLLECTION]['component_analyses']['1-0-0']
        self._check_schema_id(received_data, version_path)

        res = self.client.get(api_route_for('/schemas/api/component_analyses/blah-blah-blah'),
                              headers=accept_json)
        assert res.status_code == 404

    def test_get_server_schemas(self, accept_json):
        """Test that all server schemas are provided in all versions through the API."""
        for schema_ref, _ in load_all_server_schemas().items():
            path = api_route_for('/schemas/api/{}/{}'.format(schema_ref.name,
                                                             schema_ref.version))
            res = self.client.get(path, headers=accept_json)
            assert res.status_code == 200
            received_schema = res.json
            self._check_schema_id(received_schema, path)
            received_schema.pop('id')
            json_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                     'data',
                                     'schemas',
                                     '{}-v{}.schema.json'.
                                     format(schema_ref.name, schema_ref.version))
            with open(json_path) as f:
                assert received_schema == json.load(f)

    def test_get_worker_schemas(self, accept_json):
        """Test that all worker schemas are provided in all versions through the API."""
        for schema_ref, json_schema in load_all_worker_schemas().items():
            path = api_route_for('/schemas/component_analyses/{}/{}'.
                                 format(schema_ref.name, schema_ref.version))
            res = self.client.get(path, headers=accept_json)
            assert res.status_code == 200
            received_schema = res.json
            self._check_schema_id(received_schema, path)
            received_schema.pop('id')
            assert received_schema == json_schema


def test_get_item_skip():
    """Test the function get_item_skip()."""
    assert api_v1.get_item_skip(0, 0) == 0
    assert api_v1.get_item_skip(1, 1) == 1
    assert api_v1.get_item_skip(3, 1) == 3
    assert api_v1.get_item_skip(1, 4) == 4
    assert api_v1.get_item_skip(3, 4) == 12
    assert api_v1.get_item_skip(100, 100) == 10000


def test_get_item_relative_limit():
    """Test the function get_item_relative_limit()."""
    assert api_v1.get_item_relative_limit(1, 1) == 1
    assert api_v1.get_item_relative_limit(3, 1) == 1
    assert api_v1.get_item_relative_limit(1, 4) == 4
    assert api_v1.get_item_relative_limit(3, 4) == 4


def test_get_item_absolute_limit():
    """Test the function get_item_absolute_limit()."""
    assert api_v1.get_item_absolute_limit(0, 0) == 0
    assert api_v1.get_item_absolute_limit(1, 1) == 2
    assert api_v1.get_item_absolute_limit(3, 1) == 4
    assert api_v1.get_item_absolute_limit(3, 4) == 16


def test_get_items_for_page():
    """Test the function get_items_for_page()."""
    assert api_v1.get_items_for_page(["one", "two"], 0, 1) == ["one"]
    assert api_v1.get_items_for_page(["one", "two"], 1, 1) == ["two"]
    assert api_v1.get_items_for_page(["one", "two"], 0, 2) == ["one", "two"]
    assert api_v1.get_items_for_page(["one", "two"], 1, 2) == []


def test_paginated():
    """Test the function paginated()."""
    f = api_v1.paginated(None)
    assert f
