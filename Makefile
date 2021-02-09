REGISTRY ?= quay.io
DEFAULT_TAG = latest
IMAGE_NAME ?= bayesian-api

DOCKERFILE := Dockerfile
ifeq ($(TARGET),rhel)
	REPOSITORY ?= openshiftio/rhel-bayesian-bayesian-api
else
	REPOSITORY ?= openshiftio/bayesian-bayesian-api
endif

.PHONY: all docker-build fast-docker-build test get-image-name get-image-repository coreapi-release

all: fast-docker-build

coreapi-release:
	git show -s --format="COMMITTED_AT=%ai%nCOMMIT_HASH=%h%n" HEAD > hack/coreapi-release

docker-build: coreapi-release
	docker build --no-cache -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .
	docker tag $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) $(IMAGE_NAME)

fast-docker-build: coreapi-release
	docker build -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f $(DOCKERFILE) .
	docker tag $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) $(IMAGE_NAME)

test: fast-docker-build
	./runtest.sh

get-image-name:
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-repository:
	@echo $(REPOSITORY)

