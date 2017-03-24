"""JSL schema for component analysis endpoint that interfaces with graphdb"""
import jsl

from cucoslib.schemas import JSLSchemaBase, added_in, removed_in

ROLE_v1_0_0 = "v1-0-0"
ROLE_v1_1_0 = "v1-1-0"

class ResultData(JSLSchemaBase):
    class Options(object):
        definition_id = "result_data"
        description = "Result data"
    package = jsl.DictField(additional_properties=True)
    version = jsl.DictField(additional_properties=True)

class ResultInner(JSLSchemaBase):
    class Options(object):
        definition_id = "result_inner"
        description = "Set of Result inner"
    data = jsl.ArrayField(jsl.DocumentField(ResultData, as_ref=True), required=True)
    meta = jsl.DictField(additional_properties=True)

class Status(JSLSchemaBase):
    class Options(object):
        definition_id = "status"
        description = "Component analyses response status"
    attributes = jsl.DictField(additional_properties=True)
    code = jsl.NumberField(required=True)
    message = jsl.StringField(required=True)

class AnalysesGraphDB(JSLSchemaBase):
    class Options(object):
        definition_id = "analyses_graphdb"
        description = "Component Analysis from GraphDB"

    with removed_in(ROLE_v1_1_0) as removed_in_v1_1_0:
        removed_in_v1_1_0.requestId = jsl.StringField(required=True)
    with added_in(ROLE_v1_1_0) as added_in_v1_1_0:
        added_in_v1_1_0.request_id = jsl.StringField(required=True)

    result = jsl.DocumentField(ResultInner, as_ref=True, required=True)
    status = jsl.DocumentField(Status, as_ref=True, required=True)

THE_SCHEMA = AnalysesGraphDB
