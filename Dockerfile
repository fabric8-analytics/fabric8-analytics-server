FROM registry.centos.org/centos/centos:7
MAINTAINER Pavel Odvody <podvody@redhat.com>
ENV LANG=en_US.UTF-8

RUN useradd coreapi
# python3-pycurl is needed for Amazon SQS (boto lib), we need CentOS' rpm - installing it from pip results in NSS errors
RUN yum install -y epel-release &&\
    yum install -y gcc patch git python34-pip python34-requests httpd httpd-devel python34-devel postgresql-devel redhat-rpm-config libxml2-devel libxslt-devel python34-pycurl &&\
    yum clean all

RUN mkdir -p /coreapi
COPY ./requirements.txt /coreapi
RUN pushd /coreapi && \
    pip3 install -r requirements.txt && \
    rm requirements.txt && \
    popd


# Apply not-yet-upstream-released patches
RUN mkdir -p /tmp/install_deps/patches/
COPY hack/patches/* /tmp/install_deps/patches/
COPY hack/apply_patches.sh /tmp/install_deps/

COPY ./coreapi-httpd.conf /etc/httpd/conf.d/

ENTRYPOINT ["/usr/bin/coreapi-server.sh"]

COPY ./ /coreapi
RUN pushd /coreapi && \
    pip3 install . && \
    popd && \
    # needed for DB migrations
    find coreapi/ -mindepth 1 -maxdepth 1 \( ! -name 'alembic*' -a ! -name hack \) -exec rm -rf {} +

ENV F8A_WORKER_VERSION=16feab8340ed27e1ae8f7220e0d636016a39f32f
RUN pip3 install git+https://github.com/fabric8-analytics/fabric8-analytics-worker.git@${F8A_WORKER_VERSION}

COPY .git/ /tmp/.git
# date and hash of last commit
RUN cd /tmp/.git &&\
    git show -s --format="COMMITTED_AT=%ai%nCOMMIT_HASH=%h%n" HEAD | tee /etc/coreapi-release &&\
    rm -rf /tmp/.git/

# A temporary hack to keep Selinon up2date
COPY hack/update_selinon.sh /tmp/
RUN sh /tmp/update_selinon.sh

# Apply patches here to be also able to patch selinon
RUN cd /tmp/install_deps/ && /tmp/install_deps/apply_patches.sh

RUN yum install -y npm && npm install -g semver-ranger
