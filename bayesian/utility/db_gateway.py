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
"""All communications with Graph DB and RDS from API v2 are done here."""

import os
import json
import time
import logging
from datetime import datetime
from requests import post
from bayesian import rdb
from bayesian.utils import fetch_sa_request, retrieve_worker_result
from f8a_utils.gh_utils import GithubUtils

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from f8a_worker.models import StackAnalysisRequest

logger = logging.getLogger(__name__)
gremlin_url = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))


class GraphAnalyses:
    """Graph Analyses for Component Analyses."""

    component_analyses_query = {
        "snyk": """
            g.V().has('pecosystem', ecosystem).has('pname', name).has('version', version)
            .as('version').in('has_version').dedup().as('package').select('version')
            .coalesce(out('has_snyk_cve').as('cve').select('package','version','cve')
            .by(valueMap()),select('package','version').by(valueMap()));
            """,
    }

    ca_batch_query = """
            epv = [];packages.each {g.V().has('pecosystem', ecosystem).has('pname', it.name)
            .has('version', it.version).as('version', 'cve').select('version').in('has_version')
            .dedup().as('package').select('package', 'version', 'cve')
            .by(valueMap()).by(valueMap()).by(out('has_snyk_cve')
            .valueMap().fold()).fill(epv);};epv;
            """

    get_vuln_query = """
            g.V().has('snyk_ecosystem', ecosystem).has('package_name', within(packages)).valueMap()
            """

    get_package_query = """
            g.V().has('ecosystem', ecosystem).has('name', within(packages)).valueMap()
            """

    @classmethod
    def get_ca_data_from_graph(cls, ecosystem, package, version, vendor):
        """Query GraphDB for Component Analyses v2.

        Query vendor specific GraphDB Node Edge
        :returns: json converted data.
        """
        start = datetime.now()
        cve_info_query = cls.component_analyses_query.get(vendor)
        assert all(
            [ecosystem, package, version, vendor, cve_info_query]), "Required Parameters Missing."
        payload = {
            'gremlin': cve_info_query,
            'bindings': {
                'ecosystem': ecosystem,
                'name': package,
                'version': version
            }
        }
        logger.debug('Executing Gremlin calls with payload %s', payload)
        query_result = post(gremlin_url, data=json.dumps(payload))
        logger.info('Gremlin request took %f seconds', (datetime.now() - start).total_seconds())
        return query_result.json()

    @classmethod
    def post_gremlin(cls, query: str, bindings: dict = None) -> dict:
        """Post the given query and bindings to gremlin endpoint."""
        payload = {
            'gremlin': query,
            'bindings': bindings
        }
        started_at = time.time()
        response = post(url=gremlin_url, data=json.dumps(payload))
        response.raise_for_status()
        elapsed_time = time.time() - started_at
        logger.info("It took %s to fetch results from Gremlin.", elapsed_time)
        return response.json()

    @classmethod
    def get_batch_ca_data(cls, ecosystem: str, packages) -> dict:
        """Component Analyses Batch Call."""
        logger.debug('Executing get_batch_ca_data')
        bindings = {
            'ecosystem': ecosystem,
            'packages': packages
        }
        return GraphAnalyses.post_gremlin(cls.ca_batch_query, bindings)

    @classmethod
    def get_vulnerabilities_for_packages(cls, ecosystem: str, packages) -> dict:
        """Get vulnerabilities for given packages."""
        logger.debug('Executing get_vulnerabilities_for_packages')

        bindings = {
            'ecosystem': ecosystem,
            'packages': packages
        }
        return GraphAnalyses.post_gremlin(cls.get_vuln_query, bindings)

    @classmethod
    def get_package_details(cls, ecosystem: str, packages) -> dict:
        """Get vulnerabilities for given packages."""
        logger.debug('Executing get_package_details')

        bindings = {
            'ecosystem': ecosystem,
            'packages': packages
        }
        return GraphAnalyses.post_gremlin(cls.get_package_query, bindings)

    @classmethod
    def filter_vulnerable_packages(cls, vulnerabilities: list, package_version_map: dict) -> dict:
        """Filter vulnerable package based on timestamp in pseudo version."""
        logger.debug('Executing filter_vulnerable_packages')

        filter_vulnerabilities = {}
        gh = GithubUtils()
        for vuln in vulnerabilities:
            package_name = vuln['package_name'][0]
            if gh._is_commit_date_in_vuln_range(
               gh.extract_timestamp(
                   package_version_map[package_name]), vuln['vuln_commit_date_rules'][0]):
                if package_name not in filter_vulnerabilities:
                    filter_vulnerabilities[package_name] = []
                filter_vulnerabilities[package_name].append(vuln)

        return filter_vulnerabilities

    @classmethod
    def get_batch_ca_data_for_pseudo_version(cls, ecosystem: str, packages) -> dict:
        """Component analyses batch call only for pseudo version applicable for golang."""
        logger.debug('Executing get_batch_ca_data_for_pseudo_version')
        started_at = time.time()

        # Build unique package list and package -> version map.
        filter_packages = set()
        package_version_map = {}
        for pckg in packages:
            package_name = pckg['name'].split('@')[0]
            filter_packages.add(package_name)
            package_version_map[package_name] = pckg['version']

        vuln_response = GraphAnalyses.get_vulnerabilities_for_packages(
            ecosystem, list(filter_packages))
        vulnerabilities = GraphAnalyses.filter_vulnerable_packages(
            vuln_response.get('result', {}).get('data', []), package_version_map)
        pckg_response = GraphAnalyses.get_package_details(
            ecosystem, list(vulnerabilities.keys()))

        # Merge the package and vunlerability data into response.
        data = []
        for pckg in pckg_response.get('result', {}).get('data', []):
            data.append({
                'package': pckg,
                'version': {},
                'cve': vulnerabilities.get(pckg['name'][0], [])
            })
        pckg_response['result']['data'] = data

        elapsed_time = time.time() - started_at
        logger.info("It took %s to fetch pseudo version results.", elapsed_time)

        return pckg_response


class RdbAnalyses:
    """RDB Interface class used by stack analyses flow.

    Provides interfaces to save and read request post data for stack analyses v2.
    """

    def __init__(self, request_id, submit_time=None, manifest=None, deps=None):
        """Set request id."""
        self.request_id = request_id
        self.submit_time = submit_time
        self.manifest = manifest
        self.deps = deps

    def get_request_data(self):
        """Read request data for given request id from RDS."""
        db_result = None
        try:
            start = time.time()
            db_result = fetch_sa_request(rdb, self.request_id)
            logger.info('%s took %f seconds to fetch data', self.request_id, time.time() - start)
        except Exception as e:
            error_message = 'Internal database server error for {}.'.format(self.request_id)
            logger.exception(error_message)
            raise RDBServerException(error_message) from e

        if db_result is None:
            error_message = 'Invalid request ID {}.'.format(self.request_id)
            logger.exception(error_message)
            raise RDBInvalidRequestException(error_message)

        return db_result

    def get_stack_result(self):
        """Read and return stack result from RDS."""
        return retrieve_worker_result(rdb, self.request_id, 'stack_aggregator_v2')

    def get_recommendation_data(self):
        """Read and return recommendation data from RDS."""
        return retrieve_worker_result(rdb, self.request_id, 'recommendation_v2')

    def save_post_request(self):
        """Save the post request data into RDS."""
        try:
            start = time.time()
            insert_stmt = insert(StackAnalysisRequest).values(
                id=self.request_id,
                submitTime=self.submit_time,
                dep_snapshot=self.deps
            )
            do_update_stmt = insert_stmt.on_conflict_do_update(
                index_elements=['id'],
                set_=dict(dep_snapshot=self.deps)
            )
            rdb.session.execute(do_update_stmt)
            rdb.session.commit()
            logger.info('%s took %f seconds to save data', self.request_id, time.time() - start)
        except SQLAlchemyError as e:
            logger.exception('%s Error updating log, exception %s', self.request_id, str(e))
            raise RDBSaveException('Error while saving request {}'.format(self.request_id)) from e


class RDBSaveException(Exception):
    """Representation of RDB exception.

    Contains details information on exception caused by RDB server.
    """

    pass


class RDBInvalidRequestException(Exception):
    """Exception raised when RDB is queried with wrong / invalid request id.

    Indicate RDB could not get any result data for a given request id.
    """

    pass


class RDBServerException(Exception):
    """Exception raised when there is a n unknown exception raised while accessing RDB.

    Indicate RDB could not be reached / unknown exception raised during request.
    """

    pass
