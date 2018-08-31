#!/bin/bash

py.test -p no:cacheprovider --cov=/bayesian/bayesian/ --cov-report term-missing -vv tests/
