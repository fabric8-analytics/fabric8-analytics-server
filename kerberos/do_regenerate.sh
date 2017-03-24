#!/bin/bash

docker build -t coreapi-kerberos-regenerate -f Dockerfile.regenerate-krb5kdc .
CONTAINER=`docker run --privileged -d coreapi-kerberos-regenerate`
sleep 5
for f in /var/kerberos/krb5kdc/{.k5.EXAMPLE.COM,principal,principal.ok,principal.kadm5,principal.kadm5.lock}; do
  docker cp $CONTAINER:$f ./krb5kdc/
done
docker cp $CONTAINER:/var/keytab/httpd.keytab ./keytab/
docker rm -fv $CONTAINER
docker rmi coreapi-kerberos-regenerate
