"""Basic Metrics Collection logic."""

import time

from flask import current_app, g, request
from prometheus_client import Counter, Gauge
from prometheus_client.metrics import MetricWrapperBase
from typing import Dict, Optional
import os
from prometheus_client import CollectorRegistry
from prometheus_client.multiprocess import MultiProcessCollector


METRICS_PARAMS = {
    "requests": (
        Counter,
        {
            "name": "http_requests_total",
            "documentation": "Total count of requests by method, path, and status code.",
            "labelnames": ["method", "path_template", "status_code"],
        },
    ),
    "requests_duration": (
        Gauge,
        {
            "name": "http_requests_duration",
            "documentation": "Gauge of requests processing time by path (in seconds)",
            "labelnames": ["method", "path_template", "status_code"],
            "multiprocess_mode": 'livesum',
        },
    )
}


def get_metrics_registry() -> CollectorRegistry:
    """Initialize a observability registry."""
    prometheus_multiproc_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
    registry = CollectorRegistry()
    if prometheus_multiproc_dir:
        MultiProcessCollector(registry, path=prometheus_multiproc_dir)
    return registry


def init_metrics(registry: CollectorRegistry) -> Dict[str, MetricWrapperBase]:
    """Initialize the observability with the registry."""
    metrics = {}
    for name, init_bits in METRICS_PARAMS.items():
        metric_type, params = init_bits
        metrics[name] = metric_type(registry=registry, **params)
    return metrics


def emit_response_metrics(status_code: int, metrics: Dict[str, MetricWrapperBase]) -> None:
    """Emit metrics for a response."""
    if not metrics:
        return
    path_template = get_path_template()
    if path_template is None:
        path_template = "default"

    add_to_counter(metrics, path_template, status_code)
    add_to_guage(metrics, path_template, status_code)


def add_to_counter(metrics: Dict, path_template: str, status_code: int):
    """Build Counter."""
    method = request.method
    metrics["requests"].labels(
        method=method,
        path_template=path_template,
        status_code=status_code
    ).inc()


def add_to_guage(metrics: Dict, path_template: str, status_code: int):
    """Build Gauge."""
    method = request.method
    duration_s = time.time() - getattr(g, 'time_start')
    metrics["requests_duration"].labels(
        method=method,
        path_template=path_template,
        status_code=status_code,
    ).set(duration_s)


def get_path_template() -> Optional[str]:
    """Get the path template for the request, or fall back to plain path."""
    for route in current_app.url_map.iter_rules():
        if route.rule == request.path:
            return route.rule
    return None
