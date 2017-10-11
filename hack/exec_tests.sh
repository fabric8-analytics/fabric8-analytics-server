#!/usr/bin/bash

set -e

py.test -p no:cacheprovider -vv $@
