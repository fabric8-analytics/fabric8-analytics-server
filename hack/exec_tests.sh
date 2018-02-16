#!/usr/bin/bash

set -e

# we need no:cacheprovider, otherwise pytest will try to write to directory .cache which is in /usr under unprivileged
# user and will cause exception
py.test -p no:cacheprovider --cov=/bayesian/bayesian/ --cov-report term-missing -vv $@
