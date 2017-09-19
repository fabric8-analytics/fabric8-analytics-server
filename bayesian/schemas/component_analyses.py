"""JSL schema for component analysis endpoint"""
import jsl

from f8a_worker.schemas import JSLSchemaBaseWithRelease

# Only one version currently
ROLE_v1_0_0 = "v1-0-0"
ROLE_v1_0_1 = "v1-0-1"
ROLE_v1_1_0 = "v1-1-0"
ROLE_v1_1_1 = "v1-1-1"
ROLE_v1_1_2 = "v1-1-2"
ROLE_v1_1_3 = "v1-1-3"
ROLE_TITLE = jsl.roles.Var({
    ROLE_v1_0_0: "Component Analysis v1-0-0",
    ROLE_v1_0_1: "Component Analysis v1-0-1",
    ROLE_v1_1_0: "Component Analysis v1-1-0",
    ROLE_v1_1_1: "Component Analysis v1-1-1",
    ROLE_v1_1_2: "Component Analysis v1-1-2",
    ROLE_v1_1_3: "Component Analysis v1-1-3",
})


class AnalysisSet(jsl.Document):
    class Options(object):
        definition_id = "analysis_set"
        description = "Set of named component analyses"

    digests = jsl.DictField(additional_properties=True)
    security_issues = jsl.DictField(additional_properties=True)
    source_licenses = jsl.DictField(additional_properties=True)
    crypto_algorithms = jsl.DictField(additional_properties=True)
    languages = jsl.DictField(additional_properties=True)
    binary_data = jsl.DictField(additional_properties=True)
    static_analysis = jsl.DictField(additional_properties=True)
    metadata = jsl.DictField(additional_properties=True)
    github_details = jsl.DictField(additional_properties=True)
    redhat_downstream = jsl.DictField(additional_properties=True)
    blackduck = jsl.Var({lambda v: v == ROLE_v1_0_1 or v >= ROLE_v1_1_1:
                        jsl.DictField(additional_properties=True)})
    with jsl.Scope(lambda v: v >= ROLE_v1_1_2) as added_in_v1_1_2:
        added_in_v1_1_2.dependency_snapshot = jsl.DictField(additional_properties=True)
    with jsl.Scope(lambda v: v >= ROLE_v1_1_3) as added_in_v1_1_3:
        added_in_v1_1_3.code_metrics = jsl.DictField(additional_properties=True)


class ComponentAnalysis(JSLSchemaBaseWithRelease):
    class Options(object):
        definition_id = "component_analysis"
        description = "Software component analysis"

    ecosystem = jsl.StringField(
        description="Language ecosystem providing the component",
        required=True
    )
    package = jsl.StringField(
        description="Component name",
        required=True
    )
    version = jsl.StringField(
        description="Component version",
        required=True
    )
    latest_version = jsl.OneOfField(
        [jsl.StringField(), jsl.NullField()],
        description="Latest version available of this component (null if unknown)",
        required=True
    )
    started_at = jsl.DateTimeField(
        description="Date/time component analysis was started",
        required=True
    )
    finished_at = jsl.DateTimeField(
        description="Date/time component analysis was finished",
        required=True
    )
    access_count = jsl.NumberField(
        description="Number of times this component has been queried",
        required=True
    )
    dependents_count = jsl.Var({lambda v: v >= ROLE_v1_1_0: jsl.NumberField(
        description="Number of dependent GitHub projects",
        required=True)
    })

    analyses = jsl.DocumentField(AnalysisSet, as_ref=True, required=True)
    package_info = jsl.DictField(
        description="Additional information related to the package",
        additional_properties=True,
        required=False
    )


THE_SCHEMA = ComponentAnalysis
