"""Gunicorn config."""
# NOTE: Must be before we import or call anything that may be synchronous.
from gevent import monkey

monkey.patch_all()

import logging
from bayesian.settings import GUNICORN_SETTINGS, log_all_settings

workers = GUNICORN_SETTINGS.workers
worker_class = GUNICORN_SETTINGS.worker_class
timeout = GUNICORN_SETTINGS.timeout
preload_app = GUNICORN_SETTINGS.preload
worker_connections = GUNICORN_SETTINGS.worker_connections
reload = preload_app is not True
accesslog = "-"


def when_ready(server):  # noqa
    """Log when worker is ready to serve."""
    logger = logging.getLogger(__name__)
    logger.info(
        "Starting gunicorn with %s workers %s worker class and preload %s",
        workers,
        worker_class,
        preload_app,
    )
    log_all_settings()
