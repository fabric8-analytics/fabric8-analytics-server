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
ROLE_v2_0_0 = "v2-0-0"
ROLE_TITLE = jsl.roles.Var({
    ROLE_v1_0_0: "Component Analysis v1-0-0",
    ROLE_v1_0_1: "Component Analysis v1-0-1",
    ROLE_v1_1_0: "Component Analysis v1-1-0",
    ROLE_v1_1_1: "Component Analysis v1-1-1",
    ROLE_v1_1_2: "Component Analysis v1-1-2",
    ROLE_v1_1_3: "Component Analysis v1-1-3",
    ROLE_v2_0_0: "Component Analysis v2-0-0"
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
    blackduck = jsl.Var({lambda v: v == ROLE_v1_0_1 or v >= ROLE_v1_1_1: jsl.DictField(additional_properties=True)})
    with jsl.Scope(lambda v: v >= ROLE_v1_1_2) as added_in_v1_1_2:
        added_in_v1_1_2.dependency_snapshot = jsl.DictField(additional_properties=True)
    with jsl.Scope(lambda v: v>= ROLE_v1_1_3) as added_in_v1_1_3:
        added_in_v1_1_3.code_metrics = jsl.DictField(additional_properties=True)

with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as added_in_v2_0_0:
    class Package(jsl.Document):
        class Options(object):
            definition_id = "package_data"
            description = "Package data"
        ecosystem = jsl.ArrayField(jsl.StringField(), required=True)
        gh_forks = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_issues_last_month_closed = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_issues_last_month_opened = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_issues_last_year_closed = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_issues_last_year_opened = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_prs_last_month_closed = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_prs_last_month_opened = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_prs_last_year_closed = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_prs_last_year_opened = jsl.ArrayField(jsl.NumberField(), required=False)
        gh_stargazers = jsl.ArrayField(jsl.NumberField(), required=False)
        last_updated = jsl.ArrayField(jsl.NumberField(), required=False)
        last_updated_sentiment_score = jsl.ArrayField(jsl.StringField(), required=False)
        latest_version = jsl.ArrayField(jsl.StringField(), required=False)
        libio_contributors = jsl.ArrayField(jsl.NumberField(), required=False)
        libio_dependents_projects = jsl.ArrayField(jsl.StringField(), required=False)
        libio_dependents_repos = jsl.ArrayField(jsl.StringField(), required=False)
        libio_latest_release = jsl.ArrayField(jsl.NumberField(), required=False)
        libio_total_releases = jsl.ArrayField(jsl.StringField(), required=False)
        libio_usedby = jsl.ArrayField(jsl.StringField(), required=False)
        libio_watchers = jsl.ArrayField(jsl.NumberField(), required=False)
        name = jsl.ArrayField(jsl.StringField(), required=True)
        package_dependents_count = jsl.ArrayField(jsl.NumberField(), required=False)
        package_relative_used = jsl.ArrayField(jsl.StringField(), required=False)
        sentiment_magnitude = jsl.ArrayField(jsl.StringField(), required=False)
        sentiment_score = jsl.ArrayField(jsl.StringField(), required=False)
        tokens = jsl.ArrayField(jsl.StringField(), required=False)
        vertex_label = jsl.ArrayField(jsl.StringField(), required=False)

    class Version(jsl.Document):
        class Options(object):
            definition_id = "version_data"
            description = "Version data"
        cm_avg_cyclomatic_complexity = jsl.ArrayField(jsl.NumberField(), required=False)
        cm_loc = jsl.ArrayField(jsl.NumberField(), required=False)
        cm_num_files = jsl.ArrayField(jsl.NumberField(), required=False)
        dependents_count = jsl.ArrayField(jsl.NumberField(), required=False)
        description = jsl.ArrayField(jsl.StringField(), required=False)
        last_updated = jsl.ArrayField(jsl.NumberField(), required=False)
        licenses = jsl.ArrayField(jsl.StringField(), required=False)
        pecosystem = jsl.ArrayField(jsl.StringField(), required=True)
        pname = jsl.ArrayField(jsl.StringField(), required=True)
        shipped_as_downstream = jsl.ArrayField(jsl.BooleanField(), required=False)
        version = jsl.ArrayField(jsl.StringField(), required=True)
        vertex_label = jsl.ArrayField(jsl.StringField(), required=False)

    class ComponentData(jsl.Document):
        class Options(object):
            definition_id = "component_data"
        description = "Component data"

        package = jsl.DocumentField(Package, as_ref=True, required=True)
        version = jsl.DocumentField(Version, as_ref=True, required=True) 
    class ResultList(jsl.Document):
        class Options(object):
            definition_id = "result_list"
            description = "List of result data"
        result_data = jsl.ArrayField(jsl.DocumentField(ComponentData, as_ref=True, required=True))


class ComponentAnalysis(JSLSchemaBaseWithRelease):
    class Options(object):
        definition_id = "component_analysis"
        description = "Software component analysis"

    with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as since_v2_0_0:
        since_v2_0_0.result = jsl.DocumentField(ResultList, as_ref=True, required=True)
    
    with jsl.Scope(lambda v: v < ROLE_v2_0_0) as before_v2_0_0:   
        before_v2_0_0.ecosystem = jsl.StringField(
            description="Language ecosystem providing the component",
            required=True
        )
        before_v2_0_0.package = jsl.StringField(
            description="Component name",
            required=True
        )
        before_v2_0_0.version = jsl.StringField(
            description="Component version",
            required=True
        )
        before_v2_0_0.latest_version = jsl.OneOfField(
            [jsl.StringField(), jsl.NullField()],
            description="Latest version available of this component (null if unknown)",
            required=True
        )
        before_v2_0_0.started_at = jsl.DateTimeField(
            description="Date/time component analysis was started",
            required=True
        )
        before_v2_0_0.finished_at = jsl.DateTimeField(
            description="Date/time component analysis was finished",
            required=True
        )
        before_v2_0_0.access_count = jsl.NumberField(
            description="Number of times this component has been queried",
            required=True
        )
        before_v2_0_0.analyses = jsl.DocumentField(AnalysisSet, as_ref=True, required=True)
        before_v2_0_0.package_info = jsl.DictField(
            description="Additional information related to the package",
            additional_properties=True,
            required=False
        )

        with jsl.Scope(lambda v: v >= ROLE_v1_1_0) as between_v110_and_v200:
            between_v110_and_v200.dependents_count = jsl.NumberField(
                description="Number of dependent GitHub projects",
                required=True
            )
        

THE_SCHEMA = ComponentAnalysis
