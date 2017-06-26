#!/bin/bash

set -xe

THISDIR=`dirname $0`

TIMESTAMP="$(date +%F-%H-%M-%S)"
IMAGE_NAME="registry.devshift.net/bayesian/bayesian-api"
MIGRATIONS_IMAGE_NAME="coreapi-server-migrations"
POSTGRES_CONTAINER_NAME="coreapi-migrations-postgres-${TIMESTAMP}"
MIGRATIONS_CONTAINER_NAME="coreapi-server-migrations-${TIMESTAMP}"

docker build --pull --tag=$IMAGE_NAME -f ${THISDIR}/../../Dockerfile.server ${THISDIR}/../..
docker build -f ${THISDIR}/../Dockerfile.migrations --tag=$MIGRATIONS_IMAGE_NAME ${THISDIR}/..

gc() {
  retval=$?
  echo "Stopping containers"
  docker stop ${POSTGRES_CONTAINER_NAME} ${MIGRATIONS_CONTAINER_NAME} || :
  echo "Removing containers"
  docker rm -v ${POSTGRES_CONTAINER_NAME} ${MIGRATIONS_CONTAINER_NAME} || :
  exit $retval
}

trap gc EXIT SIGINT

docker-compose run -d --name ${POSTGRES_CONTAINER_NAME} postgres
NETWORK=`docker inspect --format '{{.NetworkSettings.Networks}}' ${POSTGRES_CONTAINER_NAME} | awk -F '[:[]' '{print $2}'`
sleep 10

# do crazy magic with quotes so that we can pass the command to the migrations image correctly
cmd="alembic upgrade head && alembic"
for i in "$@"; do
  cmd="$cmd '$i'"
done

#for MAC docker run -t -v `pwd`:/bayesian \
docker run -t -v `readlink -f ${THISDIR}/../..`:/bayesian \
  --link ${POSTGRES_CONTAINER_NAME} \
  --net=${NETWORK} \
  --name=${MIGRATIONS_CONTAINER_NAME} \
  --env=F8A_POSTGRES=postgresql://coreapi:coreapi@${POSTGRES_CONTAINER_NAME}:5432/coreapi \
  --env=PYTHONPATH=/bayesian/lib \
  ${MIGRATIONS_IMAGE_NAME} "$cmd"
