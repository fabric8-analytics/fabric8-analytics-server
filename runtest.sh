#!/bin/bash

# fail if smth fails
# the whole env will be running if test suite fails so you can debug
set -e

# for debugging this script, b/c I sometimes get
# unable to prepare context: The Dockerfile (Dockerfile.tests) must be within the build context (.)
set -x

TIMESTAMP="$(date +%F-%H-%M-%S)"
DB_CONTAINER_NAME="db-server-tests-${TIMESTAMP}"
CONTAINER_NAME="server-tests-${TIMESTAMP}"
IMAGE_NAME="docker-registry.usersys.redhat.com/bayesian/bayesian-api"
TEST_IMAGE_NAME="coreapi-server-tests"

gc() {
  retval=$?
  # FIXME: make this configurable
  echo "Stopping containers"
  docker stop ${DB_CONTAINER_NAME} ${CONTAINER_NAME} || :
  echo "Removing containers"
  docker rm ${DB_CONTAINER_NAME} ${CONTAINER_NAME} || :
  exit $retval
}

trap gc EXIT SIGINT

# Build and tag the required images if they're not yet built
# or if a rebuild has been explicitly requested
if [ "$REBUILD" == "1" ] || \
     !(docker inspect $IMAGE_NAME > /dev/null 2>&1); then
  echo "Building $IMAGE_NAME for testing"
  docker build --pull --tag=$IMAGE_NAME -f ../Dockerfile.server ..
fi

if [ "$REBUILD" == "1" ] || \
     !(docker inspect $TEST_IMAGE_NAME > /dev/null 2>&1); then
  echo "Building $TEST_IMAGE_NAME test image"
  docker build -f ./Dockerfile.tests --tag=$TEST_IMAGE_NAME .
fi

echo "Starting/creating containers:"
# NOTE: we omit pgbouncer while running tests
docker-compose run -d --name ${DB_CONTAINER_NAME} postgres
# find out some network the container is connected to
NETWORK=`docker inspect --format '{{.NetworkSettings.Networks}}' ${DB_CONTAINER_NAME} | awk -F '[:[]' '{print $2}'`
DB_CONTAINER_IP=`docker inspect --format '{{.NetworkSettings.IPAddress}}' ${DB_CONTAINER_NAME}`

echo "Waiting for postgres to fully initialize"
set +x
for i in {1..10}; do
  retcode=`curl http://${DB_CONTAINER_IP}:5432 &>/dev/null || echo $?`
  if test "$retcode" == "52"; then
    break
  fi;
  sleep 1
done;
set -x

rm -f ../logs/pylint_server.log

echo "Starting test suite"
docker run -t \
  -v "${PWD}:/bayesian:Z" \
  -v "${PWD}/../lib/cucoslib:/usr/lib/python3.4/site-packages/cucoslib:Z" \
  --link=${DB_CONTAINER_NAME} \
  --net=${NETWORK} \
  --name=${CONTAINER_NAME} \
  -e PGBOUNCER_SERVICE_HOST=${DB_CONTAINER_NAME} \
  $TEST_IMAGE_NAME ./hack/exec_tests.sh $@ tests/

docker cp ${CONTAINER_NAME}:/tmp/pylint_server.log ../logs

echo "Test suite passed \\o/"

