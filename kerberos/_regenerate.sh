#!/bin/bash

set -ex

mkdir -p /var/keytab/
printf "admin\nadmin\n" | /usr/sbin/kdb5_util create -s
/usr/sbin/kadmin.local -q "addprinc -pw admin admin/admin"
/usr/sbin/kadmin.local -q "addprinc -pw user user"
/usr/sbin/kadmin.local -q "addprinc -randkey HTTP/coreapi-server@EXAMPLE.COM"
# for clients outside of Vagrant box
/usr/sbin/kadmin.local -q "addprinc -randkey HTTP/192.168.42.42@EXAMPLE.COM"
# This is uber-ugly - the only way to add a keytab that will work for server
# running both at coreapi-server and as 192.168.42.42 seems to be creating
# the keytab for HTTP/*@EXAMPLE.COM ... yuck!
/usr/sbin/kadmin.local -q "ktadd -k /var/keytab/httpd.keytab -glob HTTP/*@EXAMPLE.COM"

chmod a+r /var/keytab/httpd.keytab
