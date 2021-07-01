"""Abstracts settings based on env variables."""


import os
import logging
from pydantic import BaseSettings, Field

logger = logging.getLogger(__name__)


class GunicornSettings(BaseSettings):
    """Gunicorn settings."""

    workers: int = Field(default=2, env="WORKER_COUNT")
    worker_class: str = Field(default="gevent", env="WORKER_CLASS")
    timeout: int = Field(default=300, env="WORKER_TIMEOUT")
    preload: bool = Field(default=True, env="WORKER_PRELOAD")
    worker_connections: int = Field(default=1024, env="WORKER_CONNECTIONS")
    metrics_port: int = Field(default=8000, env="METRICS_PORT")


class ComponentAnalysesSettings(BaseSettings):
    """ComponentAnalyses related settings."""

    batch_size: int = Field(default=10, env="COMPONENT_ANALYSES_BATCH_SIZE")
    # This must be equal to gremlin replica count for better concurrency.
    # Having more than gremlin replica might choke the overall response time.
    concurrency_limit: int = Field(default=2, env="COMPONENT_ANALYSES_CONCURRENCY_LIMIT")


GUNICORN_SETTINGS = GunicornSettings()
COMPONENT_ANALYSES_SETTINGS = ComponentAnalysesSettings()
ENABLE_USER_CACHING = os.environ.get('ENABLE_USER_CACHING', 'true') == 'true'
DB_CACHE_DIR = os.environ.get("DB_CACHE_DIR")


def log_all_settings():
    """Use for debugging."""
    logger.info("gunicorn: %s", str(GUNICORN_SETTINGS.dict()))
    logger.info("component analysis: %s", str(COMPONENT_ANALYSES_SETTINGS.dict()))
    logger.info("ENABLE_USER_CACHING: %s", ENABLE_USER_CACHING)
    logger.info("DB_CACHE_DIR: %s", DB_CACHE_DIR)
