#!/bin/bash -ex

load_jenkins_vars() {
    if [ -e "jenkins-env" ]; then
        cat jenkins-env \
          | grep -E "(DEVSHIFT_TAG_LEN|DEVSHIFT_USERNAME|DEVSHIFT_PASSWORD|JENKINS_URL|GIT_BRANCH|GIT_COMMIT|BUILD_NUMBER|ghprbSourceBranch|ghprbActualCommit|BUILD_URL|ghprbPullId)=" \
          | sed 's/^/export /g' \
          > ~/.jenkins-env
        source ~/.jenkins-env
    fi
}

prep() {
    yum -y update
    yum -y install docker git
    systemctl start docker
}

build_image() {
    # build image and tests
    make docker-build-tests
}

tag_push() {
    local target=$1
    local source=$2
    docker tag ${source} ${target}
    docker push ${target}
}

push_image() {
    local image_name
    local image_repository
    local tag
    local push_registry
    image_name=$(make get-image-name)
    image_repository=$(make get-image-repository)
    tag=$(git rev-parse --short=7 HEAD)
    push_registry="push.registry.devshift.net"

    # login first
    if [ -n "${DEVSHIFT_USERNAME}" -a -n "${DEVSHIFT_PASSWORD}" ]; then
        docker login -u ${DEVSHIFT_USERNAME} -p ${DEVSHIFT_PASSWORD} ${push_registry}
    else
        echo "Could not login, missing credentials for the registry"
        exit 1
    fi

    tag_push ${push_registry}/${image_repository}:latest ${image_name}
    tag_push ${push_registry}/${image_repository}:${tag} ${image_name}
    echo 'CICO: Image pushed, ready to update deployed app'
}

load_jenkins_vars
prep
