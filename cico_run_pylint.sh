#!/bin/bash

set -ex

prep() {
    yum -y update
    yum -y install epel-release
    yum -y install python34 python34-virtualenv
}

prep
./run-linter.sh
