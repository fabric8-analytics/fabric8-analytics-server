REGISTRY ?= quay.io
DEFAULT_TAG = latest

ifeq ($(TARGET),rhel)
    DOCKERFILE := Dockerfile.rhel
	REPOSITORY ?= openshiftio/rhel-bayesian-bayesian-api
else
    DOCKERFILE := Dockerfile
	REPOSITORY ?= openshiftio/bayesian-bayesian-api
endif

.PHONY: all docker-build fast-docker-build test get-image-name get-image-repository docker-build-tests fast-docker-build-tests

all: fast-docker-build

docker-build:
	docker build --no-cache -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .

docker-build-tests: docker-build
	docker build --no-cache -t coreapi-server-tests -f Dockerfile.tests .

fast-docker-build:
	docker build -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .

fast-docker-build-tests:
	docker build -t coreapi-server-tests -f Dockerfile.tests .

test: fast-docker-build-tests
	./runtest.sh

get-image-name:
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-repository:
	@echo $(REPOSITORY)

