# Deploying Bayesian API server

First make sure you're logged in to the right cluster and on the right project:

```
$ oc project
```

Note this guide assumes that secrets have already been deployed.

To deploy the API server, simply run:

```
./deploy.sh
```

It is possible to explicitly set a hostname for the API endpoint:

```
BAYESIAN_API_HOSTNAME="recommender.api.example.com" ./deploy.sh
```

If not provided, a random hostname will be assigned by OpenShift.

### Deployment prefix
The default deployment prefix is equal to the output of `oc whoami` command (i.e. likely your username on the cluster).
It can be overridden by the `PTH_ENV` environment variable.
Note the variable is used by `cloud-deployer` script and therefore it will be typically set to "DEV", "STAGE", or "PROD".