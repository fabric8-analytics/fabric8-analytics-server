#!/usr/bin/env python3
from collections import OrderedDict
import json
import os
import sys

if sys.version_info[0] < 3:
    print('Must be run under Python 3, since Python 2 adds trailing whitespaces to JSON')
    sys.exit(1)

from bayesian.schemas import load_all_server_schemas

here = os.path.dirname(__file__)

for ref, schema in load_all_server_schemas().items():
    # we don't want to overwrite previously generated schemas
    fname = os.path.join(here, '{}-v{}.schema.json'.format(*ref))
    if os.path.exists(fname):
        print('{} already exists, skipping'.format(fname))
        continue
    if 'definitions' in schema:
        definitions = schema['definitions'].items()
        schema['definitions'] = OrderedDict(sorted(definitions))
    # write schema
    with open(fname, 'w') as f:
        json.dump(schema, f, indent=4)
