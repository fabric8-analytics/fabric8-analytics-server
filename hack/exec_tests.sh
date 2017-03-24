#!/usr/bin/bash

set -e
DIR=$(dirname "${BASH_SOURCE[0]}")
source $DIR/coreapi-env.sh

py.test -vv $@

echo "Running pylint"
pylint --rcfile=pylint.rc "/usr/lib/python3.4/site-packages/bayesian" > /tmp/pylint_server.log || exit 0
