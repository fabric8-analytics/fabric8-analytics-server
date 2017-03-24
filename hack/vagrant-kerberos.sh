#!/bin/bash
# This script is only supposed to be used in a Vagrant box
# to make it work as a testing kdc

set -ex

sudo yum install -y epel-release
sudo yum install -y krb5-{workstation,server} haveged

# since entropy is usually low in the virtual machine, we need
#  to artificially raise it by haveged (for generating kerberos DB)
# http://championofcyrodiil.blogspot.cz/2014/01/increasing-entropy-in-vm-for-kerberos.html
sudo haveged -w 1024 -r 0

# workaround https://bugzilla.redhat.com/show_bug.cgi?id=1267266
sudo mkdir -p /etc/krb5.conf.d/
sudo cp /vagrant/server/kerberos/krb5.conf /etc/
sudo cp /vagrant/server/kerberos/kdc.conf /var/kerberos/krb5kdc/

# since CentOS kerberos version may have incompatibilities with
#  Fedora's one, we don't use pregenerated files, but generate
#  everything from scratch here using kerberos/_regenerate.sh
sudo /vagrant/server/kerberos/_regenerate.sh

# make sure that it's possible to do kinit after sshing into the box
cat >> /etc/hosts << EOF
127.0.0.1 coreapi-kdc
127.0.0.1 coreapi-server
EOF

sudo systemctl enable krb5kdc
sudo systemctl start krb5kdc
