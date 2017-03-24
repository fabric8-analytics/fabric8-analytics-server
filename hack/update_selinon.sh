#!/usr/bin/env bash
# This is a temporary hack to ensure that all containers are running same Selinon version. Selinon is still under
# development and releasing new versions each time there is some enhancement/bugfix done in Selinon would be time
# consuming and Fridolin is too lazy to do that each time O:-)

set -e

SELINON_COMMIT=25c600c
SELINONLIB_COMMIT=886025e


pip3 install -U git+https://github.com/selinon/selinon@${SELINON_COMMIT} &&
  pip3 install -U git+https://github.com/selinon/selinonlib@${SELINONLIB_COMMIT}
