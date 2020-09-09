[![Build Status](https://ci.centos.org/view/Devtools/job/devtools-fabric8-analytics-server-f8a-build-master/badge/icon)](https://ci.centos.org/view/Devtools/job/devtools-fabric8-analytics-server-f8a-build-master/)

# Fabric8-Analytics Core API Documentation

The Fabric8-Analytics API is a microservice that is responsible for:

* Serving generated analysis results to clients through API
* Scheduling new analyses based on client requests

## API information

See our [API details](API.md) for more info.

## Contributing

See our [contributing guidelines](https://github.com/fabric8-analytics/common/blob/master/CONTRIBUTING.md) for more info.

<!--- (Commenting out this section for now. Update this section once specifications for API are updated.)
## API definition

The API details are provided as a [RAML file](../docs/api/raml/api.raml).

A [JSON schema definition](tests/data/schemas/component_analyses-v1-1-3.schema.json)
is provided for the component analysis endpoint.

Additionally [JSON schema definition](tests/data/schemas/stack_analyses-v2-2-0.schema.json)
is provided for the stack analysis endpoint as well.
--->

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


## Virtualenv-based offline testing

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

If the Docker container based tests have been run, then this might complain
about mismatched locations in compiled files. Those can be deleted using:

    (bayesian) $ sudo find -name *.pyc -delete

# Accessing operational data for stack analyses

It's possible to access operational data related to a particular stack analysis request:

`/api/v1/stack-analyses/<request-id>/_debug`

Note this endpoint is not part of the public API.

### Footnotes

#### Check for all possible issues

The script named `check-all.sh` is to be used to check the sources for all detectable errors and issues. This script can be run w/o any arguments:

```
./check-all.sh
```

Expected script output:

```
Running all tests and checkers
  Check all BASH scripts
    OK
  Check documentation strings in all Python source file
    OK
  Detect common errors in all Python source file
    OK
  Detect dead code in all Python source file
    OK
  Run Python linter for Python source file
    OK
  Unit tests for this project
    OK
Done

Overal result
  OK
```

An example of script output when one error is detected:

```
Running all tests and checkers
  Check all BASH scripts
    Error: please look into files check-bashscripts.log and check-bashscripts.err for possible causes
  Check documentation strings in all Python source file
    OK
  Detect common errors in all Python source file
    OK
  Detect dead code in all Python source file
    OK
  Run Python linter for Python source file
    OK
  Unit tests for this project
    OK
Done

Overal result
  One error detected!
```

Please note that the script creates bunch of `*.log` and `*.err` files that are temporary and won't be commited into the project repository.

#### Coding standards

- You can use scripts `run-linter.sh` and `check-docstyle.sh` to check if the code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) and [PEP 257](https://www.python.org/dev/peps/pep-0257/) coding standards. These scripts can be run w/o any arguments:

```
./run-linter.sh
./check-docstyle.sh
```

The first script checks the indentation, line lengths, variable names, white space around operators etc. The second
script checks all documentation strings - its presence and format. Please fix any warnings and errors reported by these
scripts.

List of directories containing source code, that needs to be checked, are stored in a file `directories.txt`

#### Code complexity measurement

The scripts `measure-cyclomatic-complexity.sh` and `measure-maintainability-index.sh` are used to measure code complexity. These scripts can be run w/o any arguments:

```
./measure-cyclomatic-complexity.sh
./measure-maintainability-index.sh
```

The first script measures cyclomatic complexity of all Python sources found in the repository. Please see [this table](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) for further explanation on how to comprehend the results.

The second script measures maintainability index of all Python sources found in the repository. Please see [the following link](https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command) with explanation of this measurement.

You can specify command line option `--fail-on-error` if you need to check and use the exit code in your workflow. In this case the script returns 0 when no failures has been found and non zero value instead.

#### Dead code detection

The script `detect-dead-code.sh` can be used to detect dead code in the repository. This script can be run w/o any arguments:

```
./detect-dead-code.sh
```

Please note that due to Python's dynamic nature, static code analyzers are likely to miss some dead code. Also, code that is only called implicitly may be reported as unused.

Because of this potential problems, only code detected with more than 90% of confidence is reported.

List of directories containing source code, that needs to be checked, are stored in a file `directories.txt`

#### Common issues detection

The script `detect-common-errors.sh` can be used to detect common errors in the repository. This script can be run w/o any arguments:

```
./detect-common-errors.sh
```

Please note that only semantical problems are reported.

List of directories containing source code, that needs to be checked, are stored in a file `directories.txt`

#### Check for scripts written in BASH

The script named `check-bashscripts.sh` can be used to check all BASH scripts (in fact: all files with the `.sh` extension) for various possible issues, incompatibilities, and caveats. This script can be run w/o any arguments:

```
./check-bashscripts.sh
```

Please see [the following link](https://github.com/koalaman/shellcheck) for further explanation, how the ShellCheck works and which issues can be detected.

#### Code coverage report

Code coverage is reported via the codecov.io. The results can be seen on the following address:

[code coverage report](https://codecov.io/gh/fabric8-analytics/fabric8-analytics-server)

#### Commands to generate the dependency files for stack analysis call
##### Maven
```
mvn org.apache.maven.plugins:maven-dependency-plugin:3.0.2:tree -DoutputFile=/someloc/dependencies.txt -DoutputType=dot -DappendOutput=true;
```

##### NPM
```
npm install; npm list --prod --json > npmlist.json
```

##### Pypi
```
python -m pip install -r requirements.txt; python -c 'exec("""
        import pkg_resources as pr;import json,sys;gd=pr.get_distribution;res=list();
        for i in open(sys.argv[1]):
            try:
                rs={};I=gd(i);rs["package"]=I.key;rs["version"]=I.version;rs["deps"]=set();
                for j in pr.require(i):
                    for k in j.requires():
                        K=gd(k);rs["deps"].add((K.key, K.version))
                rs["deps"]=[{"package":p,"version":v}for p,v in rs["deps"]];res.append(rs)
            except: pass
        a=sys.argv[2:3]
        op=open(a[0],"w")if a else sys.stdout
        json.dump(res,op)
        """)'  requirements.txt  pylist.json
```
