#!/usr/bin/bash

# test coverage threshold
COVERAGE_THRESHOLD=70

check_python_version() {
    python3 /coreapi/tools/check_python_version.py 3 6
}

check_python_version

pip3 install -r /coreapi/tests/requirements.txt
ln -s /coreapi /bayesian
cd /coreapi

# we need no:cacheprovider, otherwise pytest will try to write to directory .cache which is in /usr under unprivileged
# user and will cause exception
py.test -p no:cacheprovider --cov=/coreapi/bayesian/ --cov-report=xml --cov-fail-under=$COVERAGE_THRESHOLD -vv $@
