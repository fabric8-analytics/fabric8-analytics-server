FROM registry.access.redhat.com/ubi8/python-36:latest

LABEL name="bayesian-api" \
      description="bayesian API server" \
      git-url="https://github.com/fabric8-analytics/fabric8-analytics-server" \
      git-path="/" \
      target-file="Dockerfile" \
      app-license="Apache 2.0"

ENV LANG=en_US.UTF-8 PYTHONDONTWRITEBYTECODE=1

RUN pip3 install --upgrade pip --no-cache-dir

ADD ./requirements.txt /coreapi/
RUN pip3 install -r /coreapi/requirements.txt --no-cache-dir

ADD hack/coreapi-release /etc/
ADD bayesian/ /coreapi/bayesian/
ADD bayesian/scripts/entrypoint.sh /coreapi/bayesian/scripts/entrypoint.sh

ENV PROMETHEUS_MULTIPROC_DIR=/tmp
ENTRYPOINT ["bash", "/coreapi/bayesian/scripts/entrypoint.sh"]
