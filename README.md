# Bayesian Core API Documentation

The Bayesian Core API is a microservice that is responsible for:

* Serving generated analysis results to clients through API
* Scheduling new analyses based on client requests

## API definition

The API details are provided as a [RAML file](../docs/api/raml/api.raml).

A [JSON schema definition](schemas/generated/component-analysis-v1-0-0.schema.json)
is provided for the component analysis endpoint.

There is also an [example API response](../docs/api/api-response-examples.md) and an
overview of the [recorded analysis metadata](../docs/api/metadata-format.md).

## Core API Access Logs

Core API access logs have following format:

```
{remote hostname} {remote logname, default '-'} {username, default '-'} {access time} "{first line of request}" {response status} {response length} {referer, default '-'} "{user agent}"
```

In terms of httpd LogFormat option, this is `%h %l %u %t \"%r\" %>s %b %{Referer}i \"%{User-agent}i\"`. See [httpd documentation](http://httpd.apache.org/docs/current/mod/mod_log_config.html#formats) for details

For example:

```
172.19.0.1 - - [18/Mar/2016:07:59:17 +0000] "GET /static/patternfly/css/patternfly.min.css HTTP/1.1" 304 - http://localhost:32000/ "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

Method of accessing logs can vary based on the way the API is deployed. See below for [instructions on accessing logs](#logs).

## Authentication

The core API currently uses kerberos for authentication. When using `docker-compose` to run, it sets up a local kerberos instance and offers a container that you can use as a client. When running via Kubernetes, it expects a keytab to be mounted at `/mnt/httpd.keytab`.

### Kerberos Authentication With docker-compose:

- if you want to use kerberos authentication, you need to explicitly use `docker-compose.kerberos.yml` in addition to `docker-compose.yml` for all commands (see below)
- note that while accessing the core API from `kerberos-client` container, you have to use `coreapi-server:5000` as the API server URL
- commandline:
  - run the system including kerberos containers

            docker-compose -f docker-compose.yml -f docker-compose.kerberos.yml up

  - open a new bash session in `kerberos-client` container

            docker-compose -f docker-compose.yml -f docker-compose.kerberos.yml run kerberos-client /bin/bash

  - get a ticket granting ticket, use password `user`

            kinit user

  - you are now authenticated and can access any kerberized endpoint of the core API server

### Kerberos Authentication With Vagrant:

- (re)run Vagrant box

        vagrant up

- if you want to authenticate from your host machine:
  - note that while accessing the core API from your host, you have to use `192.168.42.42:32000` as the API URL (the port is different - 32000 - than the one you need to use when using docker-compose - 5000)
  - install `krb5-workstation` package

            dnf install krb5-workstation

  - setup krb5 config (NOTE: it's important that you don't copy the file under the original name, since `kinit` ignores files with dots in filename under `/etc/krb5.conf.d/`)

            sudo cp kerberos/krb5.conf /etc/krb5.conf.d/bayesian

  - make sure that your `/etc/krb5.conf` file contains `includedir /etc/krb5.conf.d/` directive; if not, then add it
  - get a ticket granting ticket

            kinit user@EXAMPLE.COM

  - commandline:
    - you are now authenticated and can access any kerberized endpoint of the core API server

- if you want to authenticate from the Vagrant box itself (commandline only):
  - ssh into the Vagrant box

            vagrant ssh

  - get a ticket granting ticket, use password `user`

            kinit user

  - you are now authenticated and can access any kerberized endpoint of the core API server
  - note that while running in Vagrant box, you have to use `coreapi-server:32000` as the core API URL (the port is different - 32000 - than the one you need to use when using docker-compose - 5000)

### How the core API uses Kerberos Authentication

To make authentication easy and fast, only a single API endpoint is behind kerberos - `/api/v1/api-token`. This will retrieve a token that can be used for all subsequent API calls. The validity of the token is limited by time, currently one hour.

Assuming you have a valid kerberos ticket on your system, you can follow these instructions:
- make a POST request to `/api/v1/api-token` with kerberos negotiation, e.g. `curl -X POST --negotiate -u : coreapi-server:port/api/v1/api-token`
  - response will be something like: `{'token': 'some-string...', 'expires_at': '<timestamp>'}`
- now you can use the token to authenticate to any other part of the API for one hour; the token must be provided in `Authorization` header of requests, for example:
  - `curl -H "Authorization: token some-string" coreapi-server:5000/api/v1/ecosystems`

Issuing a GET request to `/api/v1/api-token` will return API token and its expiration timestamp, while issuing a DELETE request to this URI will expire API token of the user doing that request. Each POST call to this URL will revoke the old token and generate and return a new one.

# Running the tests locally

## Docker based API testing

From the `server/` directory, run the tests in a container using the helper
script:

    $ ./runtests.sh

(The above command assumes you have passwordless docker invocation configured -
if you don't, then `sudo` will be necessary to enable docker invocation).

If you're changing dependencies rather than just editing source code locally,
you will need images to be rebuilt when invoking `runtest.sh`. You
can set environment variable `REBUILD=1` to request image rebuilding.

If the offline virtualenv based tests have been run, then this may complain
about mismatched locations in compiled files. Those can be deleted using:

    $ find -name *.pyc -delete

NOTE: Running the container based tests is likely to cause any already
running local core API instance launched via Docker Compose to fall over due to
changes in the SELinux labels on mounted volumes, and may also cause
spurious test failures.


## Virtualenv based offline testing

Test cases marked with `pytest.mark.offline` may be executed without having a
Docker daemon running locally.

For server testing, the virtualenv should be created using *Python 3.4 or later*

To configure a virtualenv (called `bayesian` in the example) to run these
tests:

    (bayesian) $ python -m pip install -e ../lib
    (bayesian) $ python -m pip install -r requirements.txt
    (bayesian) $ python -m pip install -r tests/requirements.txt

The marked offline tests can then be run as:

    (bayesian) $ py.test -m offline tests/

If the Docker container based tests have been run, then this may complain
about mismatched locations in compiled files. Those can be deleted using:

    (bayesian) $ sudo find -name *.pyc -delete
