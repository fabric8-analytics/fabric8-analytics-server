from threading import Lock
from f8a_worker.setup_celery import init_celery, init_selinon


class Setup(object):
    _connected = False
    _setup_lock = Lock()

    def __init__(self):
        raise NotImplementedError("Unable to instantiate")

    @classmethod
    def connect_if_not_connected(cls):
        """Connect to Celery if not already connected, do it safely as we have
        concurrent server"""
        if cls._connected:
            return

        with cls._setup_lock:
            if not cls._connected:
                # We do not have to have result backend on server since we are
                # just pushing tasks to message queue
                init_celery(result_backend=False)
                init_selinon()
