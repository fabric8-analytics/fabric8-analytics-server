#!/usr/bin/env python3
# Copyright © 2021 Red Hat Inc.
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
# Author: Red Hat
"""Test Metrics."""
import os
from unittest.mock import patch

import pytest
from prometheus_client import CollectorRegistry
from prometheus_client.multiprocess import MultiProcessCollector
from bayesian.observability.metrics import (
    get_metrics_registry,
    init_metrics,
)


@pytest.fixture
def setup_metrics():
    """Set a metrics registry and metrics, use them in the app."""
    test_registry = CollectorRegistry()
    test_metrics = init_metrics(test_registry)
    with patch("bayesian.METRICS_REGISTRY", return_value=test_registry), patch(
        "bayesian.METRICS", return_value=test_metrics
    ):
        yield test_registry, test_metrics


@pytest.fixture
def registry(setup_metrics):
    """Get the test metrics registry."""
    test_registry, _ = setup_metrics
    return test_registry


@pytest.fixture
def metrics(setup_metrics):
    """Get the test metrics."""
    _, test_metrics = setup_metrics
    return test_metrics


@pytest.mark.usefixtures('client_class')
class TestMetrics():
    """Basic Tests for Metrics."""

    def test_get_metrics_reporting_registry_multiprocess(self):
        """get_metrics_reporting_registry can register a multiprocessing collector."""
        got_registry = get_metrics_registry()
        collectors = list(got_registry._collector_to_names.keys())
        assert len(collectors) == 1
        assert isinstance(collectors[0], MultiProcessCollector)

    def test_get_metrics_reporting_registry_standard(self):
        """get_metrics_reporting_registry can register a standard collector."""
        del os.environ["PROMETHEUS_MULTIPROC_DIR"]
        got_registry = get_metrics_registry()
        assert isinstance(got_registry, CollectorRegistry)
