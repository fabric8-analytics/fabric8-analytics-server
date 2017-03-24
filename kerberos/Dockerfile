FROM fedora:25

RUN dnf install -y krb5-{workstation,server}

COPY krb5.conf /etc/
COPY kdc.conf /var/kerberos/krb5kdc/
COPY krb5kdc/* /var/kerberos/krb5kdc/

ENTRYPOINT /usr/sbin/krb5kdc -P /var/run/krb5kdc.pid -n
