#!/usr/bin/bash

# test coverage threshold
COVERAGE_THRESHOLD=40

check_python_version() {
    python3 /bayesian/tools/check_python_version.py 3 6
}

check_python_version

pip3 install -r /coreapi/tests/requirements.txt
set -e

echo "*****************************************"
echo "*** Cyclomatic complexity measurement ***"
echo "*****************************************"
radon cc -s -a -i venv /coreapi/bayesian/

echo "*****************************************"
echo "*** Maintainability Index measurement ***"
echo "*****************************************"
radon mi -s -i venv /coreapi/bayesian/

echo "*****************************************"
echo "*** Unit tests ***"
echo "*****************************************"

# we need no:cacheprovider, otherwise pytest will try to write to directory .cache which is in /usr under unprivileged
# user and will cause exception
py.test -p no:cacheprovider --cov=/coreapi/bayesian/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv $@
