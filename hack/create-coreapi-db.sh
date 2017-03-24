#!/usr/bin/bash

RESULT=1
while (( $RESULT != 0 )); do
  echo "Trying to create database ...."
  # http://stackoverflow.com/a/36591842 - create db if not exists in Postgres
  PGPASSWORD=$POSTGRESQL_PASSWORD psql -h $POSTGRESQL_HOST -p $POSTGRESQL_PORT -U $POSTGRESQL_USER -d $POSTGRESQL_INITIAL_DATABASE -tc "SELECT 1 FROM pg_database WHERE datname = '${POSTGRESQL_DATABASE}'" | grep -q 1 || PGPASSWORD=$POSTGRESQL_PASSWORD psql -h $POSTGRESQL_HOST -p $POSTGRESQL_PORT -U $POSTGRESQL_USER -d $POSTGRESQL_INITIAL_DATABASE -c "CREATE DATABASE ${POSTGRESQL_DATABASE}"
  RESULT=$?
  if (( $RESULT == 0 )); then
    echo "Database created"
  else
    echo "Failed creating database, sleeping for 10 seconds"
    sleep 10
  fi
done
