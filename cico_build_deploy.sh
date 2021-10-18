#!/bin/bash

set -ex

. cico_setup.sh

# docker login before push is required for rhel build
docker_login

build_image

push_image
