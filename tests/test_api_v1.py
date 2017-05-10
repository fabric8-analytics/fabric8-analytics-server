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

from f8a_server import api_v1
from f8a_server.schemas import load_all_server_schemas
from cucoslib.enums import EcosystemBackend
from cucoslib.models import Analysis, Ecosystem, Package, Version, WorkerResult, PackageGHUsage
from cucoslib.schemas import load_all_worker_schemas

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


@pytest.mark.usefixtures('client_class', 'rdb')
class TestPaging(object):
    def _parse_link_hdr(self, hdr):
        if hdr == '':
            return {}
        links = hdr.split(',')
        res = {}
        for link in links:
            parts = link.split(';')
            res[parts[1].strip()[len('res="'):-1]] = parts[0].strip()[1:-1]
        return res

    def assert_paging(self, url, page, per_page):
        parsed = urlparse.urlparse(url)
        parsed_qs = urlparse.parse_qs(parsed.query)
        assert parsed.path == api_route_for('/packages/pypi/')
        assert parsed_qs == {'page': [str(page)], 'per_page': [str(per_page)]}

    def assert_package_names(self, json, low, high):
        packages = [i['package'] for i in json['items']]
        assert packages == list(sorted([str(n) for n in range(0, 11)]))[low:high+1]

    def test_no_previous_page(self, fill_packages_for_paging):
        res = self.client.get(api_route_for('/packages/pypi/?per_page=10'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        assert 'prev' not in hdrs
        self.assert_paging(hdrs['next'], 1, 10)
        self.assert_package_names(res.json, 0, 9)

    def test_no_next_page(self, fill_packages_for_paging):
        res = self.client.get(api_route_for('/packages/pypi/?per_page=11'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        assert len(hdrs) == 0
        self.assert_package_names(res.json, 0, 10)

        res = self.client.get(api_route_for('/packages/pypi/?per_page=150'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        assert len(hdrs) == 0
        self.assert_package_names(res.json, 0, 10)

    def test_multiple_pages(self, fill_packages_for_paging):
        res = self.client.get(api_route_for('/packages/pypi/?per_page=5'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        assert 'prev' not in hdrs
        self.assert_paging(hdrs['next'], 1, 5)
        self.assert_package_names(res.json, 0, 4)

        res = self.client.get(api_route_for('/packages/pypi/?per_page=5&page=1'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        self.assert_paging(hdrs['prev'], 0, 5)
        self.assert_paging(hdrs['next'], 2, 5)
        self.assert_package_names(res.json, 5, 9)

        res = self.client.get(api_route_for('/packages/pypi/?per_page=5&page=2'))
        hdrs = self._parse_link_hdr(res.headers['Link'])
        self.assert_paging(hdrs['prev'], 1, 5)
        assert 'next' not in hdrs
        self.assert_package_names(res.json, 10, 10)


@pytest.mark.usefixtures('client_class')
class TestApiV1Root(object):
    api_root = {
        "paths": [
            "/api/v1",
            "/api/v1/analyses",
            "/api/v1/analyses/<ecosystem>/<package>/<version>",
            "/api/v1/analyses/by-artifact-hash/<algorithm>/<artifact_hash>",
            "/api/v1/analyses/by-id/<int:analysis_id>",
            "/api/v1/component-analyses/<ecosystem>/<package>/<version>",
            "/api/v1/ecosystems",
            "/api/v1/packages/<ecosystem>",
            "/api/v1/schemas",
            "/api/v1/schemas/<collection>",
            "/api/v1/schemas/<collection>/<name>",
            "/api/v1/schemas/<collection>/<name>/<version>",
            "/api/v1/stack-analyses",
            "/api/v1/stack-analyses/<external_request_id>",
            "/api/v1/stack-analyses/by-origin/<origin>",
            "/api/v1/system/version",
            "/api/v1/user",
            "/api/v1/user-feedback",
            "/api/v1/versions/<ecosystem>/<package>",
            "/api/v1/versions/in-range/<ecosystem>"
        ]
    }

    def test_api_root(self, accept_json):
        res = self.client.get(api_route_for('/'), headers=accept_json)
        assert res.status_code == 200
        assert res.json == self.api_root


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Ecosystems(object):
    def test_get_ecosystems(self, accept_json, fill_analyses):
        expected = {
            api_v1.TOTAL_COUNT_KEY: len(fill_analyses[0]),
            'items': [
                {'ecosystem': e.name, 'url': e.url, 'backend': e.backend.name, 'package_count': 0}
                for e in sorted(fill_analyses[0], key=lambda x: x.name)
            ]
        }
        for item in expected['items']:
            if item['ecosystem'] == 'pypi':
                item['package_count'] = 2
            elif item['ecosystem'] == 'npm':
                item['package_count'] = 3
            else:
                item['package_count'] = 0

        res = self.client.get(api_route_for('/ecosystems/'), headers=accept_json)
        assert res.status_code == 200
        assert res.json == expected
        assert_pages(res)


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Packages(object):
    def test_get_packages(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/packages/pypi/'))
        assert res.status_code == 200
        assert res.json == {api_v1.TOTAL_COUNT_KEY: 2,
                            'items': [{'ecosystem': 'pypi', 'package': 'flexmock',
                                       'version_count': 2},
                                      {'ecosystem': 'pypi', 'package': 'requests',
                                       'version_count': 1}]
                            }
        assert_pages(res)

    def test_get_packages_no_such_ecosystem(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/packages/somelang/'))
        assert res.status_code == 404
        assert res.json == {'error': "Ecosystem 'somelang' does not exist."}

    def test_get_packages_empty_ecosystem(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/packages/go/'))
        assert res.status_code == 200
        assert res.json == {api_v1.TOTAL_COUNT_KEY: 0, 'items': []}
        assert_pages(res)


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Versions(object):
    def test_get_versions(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/versions/pypi/flexmock/'))
        assert res.status_code == 200
        assert res.json == {
            api_v1.TOTAL_COUNT_KEY: 2,
            'items': [{'ecosystem': 'pypi', 'package': 'flexmock', 'version': '0.10.1'},
                      {'ecosystem': 'pypi', 'package': 'flexmock', 'version': '0.9.1'}]
        }
        assert_pages(res)

    def test_get_versions_no_such_ecosystem(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/versions/somelang/package/'))
        assert res.status_code == 404
        assert res.json == {'error': "Package 'somelang/package' not tracked"}

    def test_get_versions_no_such_package(self, accept_json, fill_analyses):
        res = self.client.get(api_route_for('/versions/pypi/package/'))
        assert res.status_code == 404
        assert res.json == {'error': "Package 'pypi/package' not tracked"}


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Analysis(object):
    def _assert_json_analyses(self, expected, result, exp_accesses=0, debuginfo=False,
                              omit_analyses=False, omit_schema=False, sort=None):
        exp_json = []
        for e in expected:
            exp_json.append(e.to_dict(omit_analyses=omit_analyses))
        if sort:
            exp_json = list(sorted(exp_json, key=sort))
        for idx, e in enumerate(exp_json):
            if e['started_at']:
                e['started_at'] = e['started_at'].isoformat()
            if e['finished_at']:
                e['finished_at'] = e['finished_at'].isoformat()
            if debuginfo:
                e['id'] = result[idx]['id']
                e['_audit'] = e.pop('audit', None)
            else:
                e.pop('id', None)
                e.pop('audit', None)
                e.pop('subtasks', None)
            e['_release'] = e.pop('release')
            if exp_accesses:
                e['access_count'] = exp_accesses
            schr = api_v1.AnalysisBase.schema_ref
            if not omit_schema:
                e['schema'] = {'name': schr.name,
                               'version': schr.version,
                               'url': url_for('api_v1.get_schema_by_name_and_version__slashful',
                                              collection=api_v1.PublishedSchemas.API_COLLECTION,
                                              name = schr.name,
                                              version=schr.version,
                                              _external=True)}
        from pprint import pprint
        pprint(exp_json)
        pprint(result)
        assert exp_json == result

    def test_get_analyses_list(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses'))
        sort = lambda x: (x['ecosystem'], x['package'], x['version'], x['started_at'])
        assert res.status_code == 200
        self._assert_json_analyses(fill_analyses[3],
                                   res.json['items'],
                                   omit_analyses=True,
                                   omit_schema=True,
                                   sort=sort)
        assert res.json[api_v1.TOTAL_COUNT_KEY] == 7

    def test_get_analyses_list_custom_sorting(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses?sort=package,-started_at'))
        # we need to sort by started_at descending, so we convert it to timestamp and
        #  compare using negative value of that timestamp
        sort = lambda x: (x['package'], -time.mktime(x['started_at'].timetuple()))
        assert res.status_code == 200
        self._assert_json_analyses(fill_analyses[3],
                                   res.json['items'],
                                   omit_analyses=True,
                                   omit_schema=True,
                                   sort=sort)
        assert res.json[api_v1.TOTAL_COUNT_KEY] == 7

    def test_get_analyses_list_sorting_errors(self):
        res = self.client.get(api_route_for('/analyses?sort=unknown_attribute'))
        assert res.status_code == 400
        assert res.json['error'] == 'Analysis doesn\'t have property "unknown_attribute"'

        res = self.client.get(api_route_for('/analyses?sort=package,-package'))
        assert res.status_code == 400
        assert res.json['error'] == 'Both "-package", "package" in sort parameters'

    def test_get_analysis_for_existing_package_returns_latest(self, fill_analyses):
        exp_accesses = fill_analyses[3][1].access_count + 1
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1/'))
        assert res.status_code == 200
        self._assert_json_analyses([fill_analyses[3][1]], [res.json], exp_accesses=exp_accesses)

    def test_get_analysis_schema_compliance(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses/npm/serve-static/1.7.1/'))
        assert res.status_code == 200
        schema = self.client.get(res.json['schema']['url']).json
        jsonschema.validate(res.json, schema)

    def test_get_analysis_with_debuginfo(self, fill_analyses):
        exp_accesses = fill_analyses[3][1].access_count + 1
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1?debuginfo=true'))
        assert res.status_code == 200
        self._assert_json_analyses([fill_analyses[3][1]],
                                   [res.json],
                                   exp_accesses=exp_accesses,
                                   debuginfo=True)

    def test_get_analysis_fields(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1?fields=analyses.digests'))
        assert res.status_code == 200
        assert 'analyses' in res.json
        assert 'digests' in res.json['analyses']
        assert len(res.json['analyses']) == 1

    def test_get_analysis_by_hash_for_existing_package_returns_latest(self, fill_analyses):
        exp_accesses = fill_analyses[3][1].access_count + 1
        res = self.client.get(
            api_route_for(
                '/analyses/by-artifact-hash/sha1/6be7ae55bae2372c7be490321bbe5ead278bb51b/'))
        assert res.status_code == 200
        self._assert_json_analyses([fill_analyses[3][1]], [res.json], exp_accesses=exp_accesses)

    def test_get_analysis_by_hash_with_debuginfo(self, fill_analyses):
        exp_accesses = fill_analyses[3][1].access_count + 1
        res = self.client.get(
            api_route_for(
                '/analyses/by-artifact-hash/sha1/6be7ae55bae2372c7be490321bbe5ead278bb51b?debuginfo=True'))
        assert res.status_code == 200
        self._assert_json_analyses([fill_analyses[3][1]],
                                   [res.json],
                                   exp_accesses=exp_accesses,
                                   debuginfo=True)

    def test_get_nonexistent_analysis_by_hash(self, fill_analyses):
        res = self.client.get(
            api_route_for(
                '/analyses/by-artifact-hash/sha1/fff7ae55bae2372c7be490321bbe5ead278bb51b/'))
        assert res.status_code == 404
        assert res.json == {}

    def test_get_analysis_by_id_for_existing_package(self, app, fill_analyses):
        analysis = app.rdb.session.query(Analysis).first()
        res = self.client.get(
            api_route_for(
                '/analyses/by-id/{:d}'.format(analysis.id)))
        assert res.status_code == 200
        # The debuginfo test below ensures we're actually getting the *right*
        # analysis info back. The server doesn't hand out the IDs by default.
        assert "id" not in res.json

    def test_get_analysis_by_id_with_debuginfo(self, app, fill_analyses):
        analysis = app.rdb.session.query(Analysis).first()
        res = self.client.get(
            api_route_for(
                '/analyses/by-id/{:d}?debuginfo=True'.format(analysis.id)))
        assert res.status_code == 200
        assert res.json["id"] == analysis.id

    def test_get_nonexistent_analysis_by_id(self, fill_analyses):
        res = self.client.get(
            api_route_for(
                '/analyses/by-id/123456789123456789123456789123456789123456789'))
        assert res.status_code == 404
        assert res.json == {}

    def test_get_analysis_runs_new_if_none_exists(self, fill_analyses):
        flexmock(api_v1).should_receive('server_create_analysis').\
            with_args("pypi", "flexmock", "1.2.3", force=True).\
            and_return("<dispatcher-id>")
        res = self.client.post(api_route_for('/analyses/'), content_type='application/json',
                               data='{"ecosystem": "pypi", "package": "flexmock", "version": "1.2.3"}')
        assert res.status_code == 202
        assert res.json == {}

    def test_get_analysis_returns_202_if_no_analysis_object(self, app, fill_analyses):
        ecosystem = fill_analyses[0][0]
        flexmock(api_v1).should_receive('server_create_analysis'). \
            with_args(ecosystem.name, "foobar", "1.2.3", force=True). \
            and_return("<dispatcher-id>")
        package = Package(name='foobar', ecosystem=ecosystem)
        version = Version(identifier='1.2.3', package=package)
        app.rdb.session.add(version)
        app.rdb.session.commit()
        res = self.client.post(api_route_for('/analyses/'), content_type='application/json',
                               data='{"ecosystem": "%s", "package": "foobar", "version": "1.2.3"}' % ecosystem.name)
        assert res.status_code == 202
        assert res.json == {}

    def test_access_count(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1/'))
        assert res.json['access_count'] == 2
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1/'))
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1/'))
        assert res.json['access_count'] == 4

    def test_post_reschedule_analysis(self, fill_analyses):
        flexmock(api_v1).should_receive('server_create_analysis').\
            with_args('pypi', 'flexmock', '0.10.1', force=True).\
            and_return("<dispatcher-id>")
        res = self.client.post(api_route_for('/analyses'), content_type='application/json',
                               data='{"ecosystem": "pypi", "package": "flexmock", "version": "0.10.1"}')
        assert res.status_code == 202
        assert res.json == {}

    #def test_package_usage(self):
    #    res = self.client.get(api_route_for('/analyses/npm/arrify/1.0.1/'))
    #    assert res.json['package_info']['dependents_count'] == 100

    def test_analysis_contains_reference_to_worker_schema(self, fill_analyses):
        res = self.client.get(api_route_for('/analyses/pypi/flexmock/0.10.1/'))
        expected_url = url_for('api_v1.get_schema_by_name_and_version__slashful',
                               collection=api_v1.PublishedSchemas.COMPONENT_ANALYSES_COLLECTION,
                               name='source_licenses',
                               version='1-0-0',
                               _external=True)
        assert res.json['analyses']['source_licenses']['schema']['url'] == expected_url


@pytest.mark.usefixtures('client_class', 'live_server', 'rdb')
class TestGeneral(object):
    def test_no_redirects(self, fill_analyses):
        urls = [
            '/ecosystems',
            '/ecosystems/',
            '/packages/pypi',
            '/packages/pypi/',
            '/versions/pypi/flexmock',
            '/versions/pypi/flexmock/',
            '/analyses/pypi/flexmock/0.10.1',
            '/analyses/pypi/flexmock/0.10.1/',
        ]
        # we're using live_server here, since lots of these endpoints can fail,
        #   but we're actually only interested in whether or not we were redirected first
        # we can only get full url of the server by using url_for,
        #   but url_for only gets urls from view names, not from e.g. /api/v1/ecosystems =>
        #   workaround this by getting url of main index and then concatenating
        base_url = url_for('base_url', _external=True)
        for url in urls:
            res = requests.get(base_url + api_route_for(url), allow_redirects=False)
            assert res.status_code < 300 or res.status_code > 399

    def test_post_to_nopost_endpoint_doesnt_fail(self):
        res = self.client.post(api_route_for('/system/version/'))
        assert res.status_code == 405
        assert res.json == {'message': 'The method is not allowed for the requested URL.'}


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


@pytest.mark.usefixtures('client_class', 'rdb')
class TestApiV1Resolver(object):
    def test_resolve(self, accept_json, fill_analyses):
        ecosystem = 'npm'

        base_path = api_route_for('/versions/in-range/{}'.format(ecosystem))
        query = 'serve-static ^1.5.0'
        q = '{}?q={}'.format(base_path, query)

        res = self.client.get(q, headers=accept_json)
        rd = res.json

        assert res.status_code == 200
        assert rd['query'] == query
        assert rd['detail']['analysed']['serve-static'].pop() == '1.7.1'
