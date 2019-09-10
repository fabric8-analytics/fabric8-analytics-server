#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )"

pushd "${SCRIPT_DIR}/.." > /dev/null

shellcheck -e 2181 -e 1091 ./*.sh

popd > /dev/null
