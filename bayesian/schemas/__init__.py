"""JSL schemas for various endpoints (stack analysis, component analysis, ...)."""

from f8a_worker.schemas import BundledDynamicSchemaLibrary

_server_schemas_lib = BundledDynamicSchemaLibrary(__name__)
load_server_schema = _server_schemas_lib.load_schema
load_all_server_schemas = _server_schemas_lib.load_all_schemas
