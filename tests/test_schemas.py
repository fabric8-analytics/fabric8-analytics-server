import os

import pytest

from f8a_worker.schemas import BundledSchemaLibrary, assert_no_two_consecutive_schemas_are_same
from bayesian.schemas import load_all_server_schemas


@pytest.mark.offline
class TestGeneratedSchemas(object):
    schemas_path = os.path.join("data", "schemas")

    def test_dynamic_schemas_against_generated(self):
        """This test checks that previously generated schemas haven't changed
        by later modifications to the Python definitions.
        When you define new schemas or new versions of schemas, you'll need
        to run data/schemas/generate.py to get them generated.
        """
        all_schemas = load_all_server_schemas()
        test_library = BundledSchemaLibrary(self.schemas_path, __package__)
        for ref, schema in all_schemas.items():
            assert test_library.load_schema(ref) == schema


@pytest.mark.offline
class TestSchemaSequence:
    def test_no_two_consecutive_schemas_are_same(self):
        assert_no_two_consecutive_schemas_are_same(load_all_server_schemas)
