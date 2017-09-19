#!/bin/bash

# fail if smth fails
# the whole env will be running if test suite fails so you can debug
set -e

# for debugging this script, b/c I sometimes get
# unable to prepare context: The Dockerfile (Dockerfile.tests) must be within the build context (.)
set -x

here=$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)

TIMESTAMP="$(date +%F-%H-%M-%S)"
DB_CONTAINER_NAME="db-server-tests-${TIMESTAMP}"
CONTAINER_NAME="server-tests-${TIMESTAMP}"
IMAGE_NAME=${IMAGE_NAME:-registry.devshift.net/bayesian/bayesian-api}
TEST_IMAGE_NAME="coreapi-server-tests"
POSTGRES_IMAGE_NAME="registry.centos.org/sclo/postgresql-94-centos7:latest"

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
  docker build --pull --tag=$IMAGE_NAME .
fi

if [ "$REBUILD" == "1" ] || \
     !(docker inspect $TEST_IMAGE_NAME > /dev/null 2>&1); then
  echo "Building $TEST_IMAGE_NAME test image"
  docker build -f Dockerfile.tests --tag=$TEST_IMAGE_NAME .
fi

echo "Starting/creating containers:"
# NOTE: we omit pgbouncer while running tests
docker run -d --env-file tests/postgres.env --name ${DB_CONTAINER_NAME} ${POSTGRES_IMAGE_NAME}
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


# mount f8a_worker, if available (won't be in CI)
f8a_worker_path="${here}/../worker/f8a_worker"
if [ -d ${f8a_worker_path} ]; then
    f8a_worker_vol="${f8a_worker_path}:/usr/lib/python3.4/site-packages/f8a_worker:ro,Z"
fi

echo "Starting test suite"
docker run -t \
  -v "${here}:/bayesian:ro,Z" \
  ${f8a_worker_vol:+-v} ${f8a_worker_vol:-} \
  --link=${DB_CONTAINER_NAME} \
  --net=${NETWORK} \
  --name=${CONTAINER_NAME} \
  -e PGBOUNCER_SERVICE_HOST=${DB_CONTAINER_NAME} \
  -e DEPLOYMENT_PREFIX='test' \
  $TEST_IMAGE_NAME $@ tests/

echo "Test suite passed \\o/"

