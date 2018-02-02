#!/usr/bin/bash

set -e

# NOTE: the --python-eggs /home/coreapi is there before I figure out a proper solution
#   https://github.com/GrahamDumpleton/mod_wsgi/issues/125 or upstream fixes it
# TIMEOUT params --request-timeout socket-timeout should be added for requests taking longer than expected 
exec mod_wsgi-express start-server \
                      --entry-point bayesian \
                      --application-type module \
                      --callable-object app \
                      --port 5000 \
                      --user coreapi \
                      --group coreapi \
                      --processes 3 \
                      --threads 1 \
                      ${!F8A_DEBUG:---reload-on-changes} \
                      --access-log \
                      --access-log-format "%h %l %u %t \"%r\" %>s %b %{Referer}i \"%{User-agent}i\"" \
                      --log-to-terminal \
                      --python-eggs /home/coreapi \
                      --include-file /etc/httpd/conf.d/coreapi-httpd.conf \
                      --modules-directory /usr/lib64/httpd/modules \
                      --header-buffer-size 65500 \
                      --socket-timeout 600 \
                      --queue-timeout 600 \
