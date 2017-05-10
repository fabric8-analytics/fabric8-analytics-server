#!/usr/bin/bash

set -e
DIR=$(dirname "${BASH_SOURCE[0]}")
source $DIR/coreapi-env.sh

py.test -p no:cacheprovider -vv $@

echo "Running pylint"
pylint --rcfile=pylint.rc "/usr/lib/python3.4/site-packages/f8a_server" > /tmp/pylint_server.log || exit 0
