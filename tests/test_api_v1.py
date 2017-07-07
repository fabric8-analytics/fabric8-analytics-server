import datetime
import json
import time
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
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult, PackageGHUsage
from f8a_worker.schemas import load_all_worker_schemas

def api_route_for(route):
    return '/api/v1' + route


def assert_pages(response, p=None, n=None):
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
        Analysis(version=versions[0], started_at=now),                    # pypi/flexmock/0.10.1
        Analysis(version=versions[0], started_at=later, access_count=1),  # pypi/flexmock/0.10.1
        Analysis(version=versions[1], started_at=even_later),             # pypi/flexmock/0.9.1
        Analysis(version=versions[2], started_at=now),                    # pypi/requests/2.0.0
        Analysis(version=versions[3], started_at=later),                  # npm/sequence/2.2.1
        Analysis(version=versions[4], started_at=now, finished_at=later), # npm/arrify/1.0.1
        Analysis(version=versions[5], started_at=now, finished_at=later,
                 release='npm:serve-static:1.7.1'),                      # npm/serve-static/1.7.1
    ]
    # worker results that correspond to analyses above
    worker_results = [
        WorkerResult(worker='digests', analysis=analyses[1],
                    task_result={'details': [{'artifact': True,
                                                'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}),
        WorkerResult(worker='static_analysis', task_result={'details': []}, analysis=analyses[1]),
        WorkerResult(worker='source_licenses',
                     task_result={'schema': {'name': 'source_licenses', 'version': '1-0-0'}},
                     analysis=analyses[1])
    ]
    package_gh_usage = [
        PackageGHUsage(name='arrify', count=100, ecosystem_backend='npm')
    ]
    for a in ecosystems + packages + versions + analyses + worker_results + package_gh_usage:
        app.rdb.session.add(a)
        app.rdb.session.commit()

    return (ecosystems, packages, versions, analyses, worker_results, package_gh_usage)


@pytest.fixture
def fill_packages_for_paging(app, request):
    e = Ecosystem(name='pypi', backend=EcosystemBackend.pypi)
    app.rdb.session.add(e)
    for p in range(0, 11):
        app.rdb.session.add(Package(ecosystem=e, name=str(p)))

    app.rdb.session.commit()
    # no cleanup (we're recreating DB after every test case)

@pytest.mark.usefixtures('client_class')
class TestApiV1Root(object):
    api_root = {
        "paths": [
            "/api/v1",
            "/api/v1/component-analyses/<ecosystem>/<package>/<version>",
            "/api/v1/component-search/<package>",
            "/api/v1/schemas",
            "/api/v1/schemas/<collection>",
            "/api/v1/schemas/<collection>/<name>",
            "/api/v1/schemas/<collection>/<name>/<version>",
            "/api/v1/stack-analyses",
            "/api/v1/stack-analyses-v2",
            "/api/v1/stack-analyses-v2/<external_request_id>",
            "/api/v1/stack-analyses/<external_request_id>",
            "/api/v1/stack-analyses/by-origin/<origin>",
            "/api/v1/system/version",
            "/api/v1/user-feedback"
        ]
    }

    def test_api_root(self, accept_json):
        res = self.client.get(api_route_for('/'), headers=accept_json)
        assert res.status_code == 200
        assert res.json == self.api_root

@pytest.mark.usefixtures('client_class', 'rdb')
class TestUser(object):
    pass  # TODO


@pytest.mark.usefixtures('client_class')
class TestApiV1SystemVersion(object):
    def test_get_system_version(self, accept_json):
        res = self.client.get(api_route_for('/system/version/'), headers=accept_json)
        assert res.status_code == 200
        assert set(res.json.keys()) == {'committed_at', 'commit_hash'}


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Schemas(object):

    def _check_schema_id(self, received_schema, expected_path):
        """Helper to check schema ID added by the API server"""
        expected_id = 'http://localhost' + expected_path + '/'
        assert received_schema['id'] == expected_id

    def test_get_all_schemas(self, accept_json):
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
        version_path = api_route_for('/schemas/api/component_analyses/1-0-0')
        res = self.client.get(version_path, headers=accept_json)
        assert res.status_code == 200
        received_data = res.json
        assert received_data == api_v1.PublishedSchemas.\
            schema_collections[api_v1.PublishedSchemas.API_COLLECTION]['component_analyses']['1-0-0']
        self._check_schema_id(received_data, version_path)

        res = self.client.get(api_route_for('/schemas/api/component_analyses/blah-blah-blah'),
                              headers=accept_json)
        assert res.status_code == 404

    def test_get_server_schemas(self, accept_json):
        # test all server schemas are provided in all versions through the API
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
        # test all worker schemas are provided in all versions through the API
        for schema_ref, json_schema in load_all_worker_schemas().items():
            path = api_route_for('/schemas/component_analyses/{}/{}'.
                                format(schema_ref.name, schema_ref.version))
            res = self.client.get(path, headers=accept_json)
            assert res.status_code == 200
            received_schema = res.json
            self._check_schema_id(received_schema, path)
            received_schema.pop('id')
            assert received_schema == json_schema

