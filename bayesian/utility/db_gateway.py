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
import logging
from datetime import datetime
from requests import post
from bayesian import rdb
from bayesian.exceptions import HTTPError
from bayesian.utils import (fetch_sa_request,
                            retrieve_worker_result)

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects.postgresql import insert

from f8a_worker.models import StackAnalysisRequest

logger = logging.getLogger(__file__)
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
            """
    }

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
        logger.debug("Executing Gremlin calls with payload {}".format(payload))
        query_result = post(gremlin_url, data=json.dumps(payload))
        elapsed_seconds = (datetime.now() - start).total_seconds()
        logger.info("Gremlin request took {} seconds.".format(elapsed_seconds))
        return query_result.json()


class RdbAnalyses:
    """RDB Interface class used by stack analyses flow.

    Provides interfaces to save and read request post data for stack analyses v2.
    """

    @classmethod
    def get_request_data(cls, request_id):
        """Read request data for given request id from RDS."""
        db_result = fetch_sa_request(rdb, request_id)
        if db_result is None:
            error_message = 'Invalid request ID {}.'.format(request_id)
            logger.exception(error_message)
            raise HTTPError(404, error_message)
        return db_result

    @classmethod
    def get_stack_result(cls, request_id):
        """Read and return stack result from RDS."""
        return retrieve_worker_result(rdb, request_id, 'stack_aggregator_v2')

    @classmethod
    def get_recommendation_data(cls, request_id):
        """Read and return recommendation data from RDS."""
        return retrieve_worker_result(rdb, request_id, 'recommendation_v2')

    @classmethod
    def save_post_request(cls, request_id, submit_time, manifest, deps):
        """Save the post request data into RDS."""
        try:
            insert_stmt = insert(StackAnalysisRequest).values(
                id=request_id,
                submitTime=submit_time,
                requestJson={'manifest': manifest},
                dep_snapshot=deps
            )
            do_update_stmt = insert_stmt.on_conflict_do_update(
                index_elements=['id'],
                set_=dict(dep_snapshot=deps)
            )
            rdb.session.execute(do_update_stmt)
            rdb.session.commit()
        except SQLAlchemyError as e:
            logger.exception("Error updating log for request {}, exception {}".format(
                request_id, e))
            raise HTTPError(500, 'Error while saving request {}'.format(request_id))
