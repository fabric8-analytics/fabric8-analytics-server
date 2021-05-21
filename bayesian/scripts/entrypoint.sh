#!/usr/bin/env sh
export PYTHONPATH=/coreapi
export PROMETHEUS_MULTIPROC_DIR=/tmp
gunicorn -b 0.0.0.0:5000 -c /coreapi/bayesian/conf/gunicorn.py bayesian:app --log-level $FLASK_LOGGING_LEVEL
