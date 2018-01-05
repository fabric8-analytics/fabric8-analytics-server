"""JSL schema for the version resolution resolver."""
import jsl

from f8a_worker.schemas import JSLSchemaBase


ROLE_v1_0_0 = "v1_0_0"


class VersionResolutionDetail(JSLSchemaBase):
    """Class with the schema definition based on JSL domain specific language."""

    class Options:
        """A container for options."""

        description = "Version range resolver_detail"
        definition_id = "version_range_resolver_detail"

    difference = jsl.ArrayField(required=True)
    analysed = jsl.DictField(required=True)
    upstream = jsl.DictField(required=True)


class VersionRangeResolver(JSLSchemaBase):
    """Class with the schema definition based on JSL domain specific language."""

    class Options:
        """A container for options."""

        description = "Version range resolver"
        definition_id = "version_range_resolver"

    resolved_at = jsl.DateTimeField(required=True)
    query = jsl.StringField(required=True)
    detail = jsl.DocumentField(VersionResolutionDetail, required=True)


THE_SCHEMA = VersionRangeResolver
