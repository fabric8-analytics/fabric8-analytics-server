#!/bin/bash

set -ex

prep() {
    yum -y update
    yum -y install epel-release
    yum -y install python36 python36-virtualenv which
}

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

prep
check_python_version
./qa/check-docstyle.sh
