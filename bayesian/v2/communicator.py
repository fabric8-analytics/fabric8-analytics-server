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
# Author: Deepak Sharma <deepshar@redhat.com>
#
"""All communications with Graph DB and RDS from API v2 are done here."""

from datetime import datetime
import logging
from requests import post
import os
import json

logger = logging.getLogger(__file__)
gremlin_url = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))


class GraphAnalyses:
    """Graph Analyses for Component Analyses."""

    def __init__(self, ecosystem, package, version):
        """For Flows related to Security Vendor Integrations."""
        self.ecosystem = ecosystem
        self.version = version
        self.package = package

    def get_data_from_graph(self):
        """Query GraphDB for Component Analyses v2.

        Query vendor specific GraphDB Node Edge
        :returns: json converted data.
        """
        start = datetime.now()
        cve_info_query = """
        g.V().has('pecosystem', ecosystem).has('pname', name).has('version', version)
        .as('version').in('has_version').dedup().as('package').select('version')
        .coalesce(out('has_snyk_cve').as('cve').select('package','version','cve')
        .by(valueMap()),select('package','version').by(valueMap()));
        """
        payload = {
            'gremlin': cve_info_query,
            'bindings': {
                'ecosystem': self.ecosystem,
                'name': self.package,
                'version': self.version
            }
        }
        logger.debug("Executing Gremlin calls with payload {}".format(payload))
        query_result = post(gremlin_url, data=json.dumps(payload))
        elapsed_seconds = (datetime.now() - start).total_seconds()
        logger.info("Gremlin request took {} seconds.".format(elapsed_seconds))
        return query_result.json()
