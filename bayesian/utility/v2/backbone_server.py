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
"""Backbone server interface to be used by stack analyses API v2 flow."""

import os
import time
import logging
from requests_futures.sessions import FuturesSession

logger = logging.getLogger(__name__)


class BackboneServer:
    """Backbone server interface used by stack analyses flow.

    It implements methods that are required to fire backbone API to initiate aggregator and
    recommendor api.
    """

    # Read backbone API end-point from application configuraton.
    backbone_host = os.getenv('F8_API_BACKBONE_HOST', 'localhost')

    # Create global session object
    session = FuturesSession(max_workers=int(os.getenv('FUTURES_SESSION_WORKER_COUNT', '100')))

    @classmethod
    def post_aggregate_request(cls, body, params):
        """Make a post call to backbone aggregator api."""
        try:
            logger.debug('Aggregator request for backbone host: %s body: %s params: %s',
                         cls.backbone_host, body, params)

            # Post Backbone stack_aggregator call.
            start = time.time()
            BackboneServer.session.post(
                '{}/api/v2/stack_aggregator'.format(BackboneServer.backbone_host),
                json=body,
                params=params)
            logger.debug('%s took %f seconds for /api/v2/stack_aggregator',
                         body['external_request_id'], time.time() - start)
        except Exception as e:
            logger.exception('Aggregator api throws exception %s', str(e))
            raise BackboneServerException('Error while reaching aggregator service') from e

    @classmethod
    def post_recommendations_request(cls, body, params):
        """Make a post call to backbone recommender api."""
        try:
            logger.debug('Recommendation request for backbone host: %s body: %s params: %s',
                         cls.backbone_host, body, params)

            # Post Backbone recommender call.
            start = time.time()
            BackboneServer.session.post(
                '{}/api/v2/recommender'.format(BackboneServer.backbone_host),
                json=body,
                params=params)
            logger.debug('%s took %f seconds for /api/v2/recommender',
                         body['external_request_id'], time.time() - start)
        except Exception as e:
            logger.exception('Recommender api throws exception %s', str(e))
            raise BackboneServerException('Error while reaching recommender service') from e


class BackboneServerException(Exception):
    """Representation of Backbone server exception.

    Contains details information on exception caused by backbone server request.
    """

    pass
