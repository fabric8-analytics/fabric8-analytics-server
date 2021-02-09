"""Abstracts settings based on env variables."""


from pydantic import BaseSettings, Field


class GunicornSettings(BaseSettings):
    """Gunicorn settings."""

    workers: int = Field(default=2, env="WORKER_COUNT")
    worker_class: str = Field(default="gevent", env="WORKER_CLASS")
    timeout: int = Field(default=300, env="WORKER_TIMEOUT")
    preload: bool = Field(default=True, env="WORKER_PRELOAD")
    worker_connections: int = Field(default=1024, env="WORKER_CONNECTIONS")


GUNICORN_SETTINGS = GunicornSettings()
