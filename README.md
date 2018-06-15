[![Build Status](https://ci.centos.org/view/Devtools/job/devtools-fabric8-analytics-server-f8a-build-master/badge/icon)](https://ci.centos.org/view/Devtools/job/devtools-fabric8-analytics-server-f8a-build-master/)

# Fabric8-Analytics Core API Documentation

The Fabric8-Analytics API is a microservice that is responsible for:

* Serving generated analysis results to clients through API
* Scheduling new analyses based on client requests

## Contributing

See our [contributing guidelines](https://github.com/fabric8-analytics/common/blob/master/CONTRIBUTING.md) for more info.

## API definition

The API details are provided as a [RAML file](../docs/api/raml/api.raml).

A [JSON schema definition](tests/data/schemas/component_analyses-v1-1-3.schema.json)
is provided for the component analysis endpoint.

Additionally [JSON schema definition](tests/data/schemas/stack_analyses-v2-2-0.schema.json)
is provided for the stack analysis endpoint as well.

## Core API Access Logs

Core API access logs have following format:

```
{remote hostname} {remote logname, default '-'} {username, default '-'} {access time} "{first line of request}" {response status} {response length} {referer, default '-'} "{user agent}"
```

In terms of httpd LogFormat option, this is `%h %l %u %t \"%r\" %>s %b %{Referer}i \"%{User-agent}i\"`. See [httpd documentation](http://httpd.apache.org/docs/current/mod/mod_log_config.html#formats) for details.

For example:

```
172.19.0.1 - - [18/Mar/2016:07:59:17 +0000] "GET /static/patternfly/css/patternfly.min.css HTTP/1.1" 304 - http://localhost:32000/ "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0"
```

Method of accessing logs can vary based on the way the API is deployed. See below for [instructions on accessing logs](#logs).

## Docker based API testing

From the top-level git directory, run the tests in a container using the helper
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

_NOTE_: Running the container based tests is likely to cause any already
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

# Accessing operational data for stack analyses

It's possible to access operational data related to a particular stack analysis request:

`/api/v1/stack-analyses/<request-id>/_debug`

Note this endpoint is not part of the public API. 

### Footnotes

#### Coding standards

- You can use scripts `run-linter.sh` and `check-docstyle.sh` to check if the code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) and [PEP 257](https://www.python.org/dev/peps/pep-0257/) coding standards. These scripts can be run w/o any arguments:

```
./run-linter.sh
./check-docstyle.sh
```

The first script checks the indentation, line lengths, variable names, white space around operators etc. The second
script checks all documentation strings - its presence and format. Please fix any warnings and errors reported by these
scripts.

#### Code complexity measurement

The scripts `measure-cyclomatic-complexity.sh` and `measure-maintainability-index.sh` are used to measure code complexity. These scripts can be run w/o any arguments:

```
./measure-cyclomatic-complexity.sh
./measure-maintainability-index.sh
```

The first script measures cyclomatic complexity of all Python sources found in the repository. Please see [this table](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) for further explanation how to comprehend the results.

The second script measures maintainability index of all Python sources found in the repository. Please see [the following link](https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command) with explanation of this measurement.


