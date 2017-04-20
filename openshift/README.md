# Deploying Bayesian API server

First make sure you're logged in to the right cluster and on the right project:

```
$ oc project
```

Note this guide assumes that secrets and config maps have already been deployed.

To deploy the API server, simply run:

```
./deploy.sh
```

It is possible to explicitly set a hostname for the API endpoint:

```
BAYESIAN_API_HOSTNAME="recommender.api.example.com" ./deploy.sh
```

If not provided, a random hostname will be assigned by OpenShift.

