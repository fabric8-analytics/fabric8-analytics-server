import os

from cucoslib.utils import json_serial


# Disable CDN support to mitigate potential risks connected to it
BOOTSTRAP_SERVE_LOCAL = True

DEBUG = os.getenv('CCS_DEBUG', False)

# DB Settings
SQLALCHEMY_DATABASE_URI = os.getenv('CCS_POSTGRES',
                                    default='postgres://coreapi:coreapi@localhost:5432/coreapi')

# Don't attach custom messages to 404 errors with flask-restful
ERROR_404_HELP = False

JSONIFY_PRETTYPRINT_REGULAR = True
RESTFUL_JSON = {'default': json_serial, 'indent': 4, 'separators': (',', ': ')}

# Don't do this in production!
SECRET_KEY = 'devkey'
# length of token life in seconds
API_TOKEN_LIFETIME = 3600

# Info about deployed version
SYSTEM_VERSION = os.getenv('CCS_SYSTEM_VERSION', default='/etc/coreapi-release')

#BAYESIAN_ANALYTICS_URL = os.getenv('BAYESIAN_ANALYTICS_URL','http://cucos-01.lab.eng.brq.redhat.com:32100')
BAYESIAN_ANALYTICS_URL = os.getenv('BAYESIAN_ANALYTICS_URL','http://recommendationapi-server:5000')
GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format\
                            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
                            port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
BAYESIAN_PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs73IBTo0rX2m9bGJGOFqNtD2XiN6Y3mLjYDnBILRHVQ3fyZn
Ty/pRC+aKQl/rFbJbv0cXH/WdqOUGv4o5csVcaR7CPWPPNJg4RrkgtrJGAY5Zxu0
A4SflyUI6RMnxbrleP/3+bHjS5W4xFUtX/uL8Um+wlwuR26tPeQAe5HyGNo/mmDN
zqohQGVca89qKf/HFnKmYLeMcaWQAH/o0KSKyZVEKlG689y3K0Tq6XYBC+SkOIrs
Wcg71ZrX6azm8DPBa6/hSck619H+ILe7VwjXpZ4sS5sLo10E0sSHNZb57o8MpGTP
BHQPgKNNnHGlTn2MyzmLPZm8OCr+KuFtmCxOMwIDAQABAoIBAAwhZ8lqhzmaPFVi
mPUT6X4vliD+Vfk2r8NqCq1UQtau41vydJB0lFKkv8u7N2GjLc8OyAY6Hng9S/aS
ZqIzlYvo5ODS6craC+3FSdzG9UFo0iDyTrDaF4c02agZQdrnZStIYyz343YrcZ/W
e8x5hpVPO8+UNw9dGdYOeDXewK8Klq+501HUlUOoJ4AV+heCN5Dxt8z95eh59+z3
oJmAZmHxCX0YnP+K8xQiySindCXqqAB3KB+DFEI/3ofhRUA4Vo0LiqcRp9s4Sw8b
mi0FwwRSLRRQB4U44xrlh7txtW64nt+bUXvguS7YNj8FxW8dGTFa+EXraGn8nQwj
SN4s82ECgYEA5iA2PlvCi9bHTJABdFKC2sW9HhBnAe12+Ok5Bntp+ysQ97PaqoIP
jLO4JJt9VfBKQ0QgtZf8WT/O8RMBvBt9wBXZvDkKa5hKS3xYatA+9eC/dNCwi/H4
VJjCOLLrr8m9C8TQihEUOfYZzNiarZfiCFall2s2ixsfgSEOIBpPkcMCgYEAx/NV
95fz9t4L2Y3QQ+SNAluhwKWlZdtpxwTICa7xD6DdlNysigozWD6aw6yvLFSu7jsi
WgZQU30TGx44CbIQqEt4g30xeQPn4IRie0Nc5JmuTnV4FMZ+44UoTAXp7BCs3k5o
KPvQDvt+nc6L3y3dp9nqRZyUBcwDJt7cGZrtmtECgYEAgirKQ++HVa4BQW9bQz7A
wZqD5JOGkHKPjy/sj5wTUH0FtfbHwxaaUQ3/JMXG2Wt3tiC9F7qGhL0xAu+rVYl/
Ub2KUYs6N64GqDgHkzODyXR9F0hL9HzD6KYXhha+dcp44kVLaC1M8ZQg99u1cmes
9OZ99+4vBfQrl9DouoPnah0CgYACXhc+f0YcPjTVtqAoraQdywf3R/7VXeu6t4vG
0ZN5I+Z7xMEmQUiqWtNqTbklRTttBrY5aqm401pOj+UJ+FnKJFqg8/KKBEnSlr6z
xvBqpIcz1qA9XrxR5Vm8zLUgXnItj7AcDB9CjifJppBxbBGb0zC68keuaeP/qdPh
WbxGgQKBgEG0Ply4Je70sXe2ZxZupkuOob4/Mp1Sgw+UB5cPiQlN0iC23UcKdN9z
ODA3tTXCRh4WGd4gzCirf42qTB4kcalWsXua9ckFHDsrkkMn3bitUbnThGwe+jA3
7PSLZ0BnksFNkTCKZmP1m+CJ6tn2ANXtQx1JrK8ineAq1FV9EzZ/
-----END RSA PRIVATE KEY-----
"""
BAYESIAN_PUBLIC_KEY = os.getenv('BAYESIAN_AUTH_KEY', '')
