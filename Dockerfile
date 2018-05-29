FROM registry.centos.org/centos/centos:7

ENV LANG=en_US.UTF-8 \
    F8A_WORKER_VERSION=3cdfe6c

RUN useradd -d /coreapi coreapi

# https://copr.fedorainfracloud.org/coprs/fche/pcp/
# https://copr.fedorainfracloud.org/coprs/jpopelka/mercator/
COPY hack/_copr_fche_pcp.repo hack/_copr_jpopelka-mercator.repo /etc/yum.repos.d/

# python3-pycurl is needed for Amazon SQS (boto lib), we need CentOS' rpm - installing it from pip results in NSS errors
RUN yum install -y epel-release &&\
    yum install -y gcc patch git python34-pip python34-requests httpd httpd-devel python34-devel postgresql-devel redhat-rpm-config libxml2-devel libxslt-devel python34-pycurl pcp mercator &&\
    yum clean all

COPY ./requirements.txt /coreapi/
RUN pushd /coreapi && \
    pip3 install -r requirements.txt && \
    rm requirements.txt && \
    popd

COPY ./coreapi-httpd.conf /etc/httpd/conf.d/

# Create & set pcp dirs
RUN mkdir -p /etc/pcp /var/run/pcp /var/lib/pcp /var/log/pcp  && \
    chgrp -R root /etc/pcp /var/run/pcp /var/lib/pcp /var/log/pcp && \
    chmod -R g+rwX /etc/pcp /var/run/pcp /var/lib/pcp /var/log/pcp

COPY ./ /coreapi
RUN pushd /coreapi && \
    pip3 install --upgrade pip>=10.0.0 && pip3 install . &&\
    popd && \
    # needed for DB migrations
    find coreapi/ -mindepth 1 -maxdepth 1 \( ! -name 'alembic*' -a ! -name hack \) -exec rm -rf {} +

RUN pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@${F8A_WORKER_VERSION}

# Required by the solver task in worker to resolve dependencies from package.json
RUN npm install -g semver-ranger

RUN git ls-remote --heads https://github.com/fabric8-analytics/fabric8-analytics-server/ | grep "refs/heads/master" | cut -f1 | tee /etc/coreapi-release

COPY hack/coreapi-server.sh hack/server+pmcd.sh /usr/bin/

EXPOSE 44321

CMD ["/usr/bin/server+pmcd.sh"]

