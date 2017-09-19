import jsl

from f8a_worker.schemas import JSLSchemaBase, added_in, removed_in

ROLE_v1_0_0 = "v1_0_0"
ROLE_v1_1_0 = "v1_1_0"
ROLE_v1_2_0 = "v1_2_0"
ROLE_v2_0_0 = "v2_0_0"
ROLE_v2_0_1 = "v2_0_1"
ROLE_v2_0_2 = "v2_0_2"
ROLE_v2_0_3 = "v2_0_3"
ROLE_v2_1_0 = "v2_1_0"
ROLE_v2_1_1 = "v2_1_1"
ROLE_v2_1_2 = "v2_1_2"
ROLE_v2_1_3 = "v2_1_3"
ROLE_v2_1_4 = "v2_1_4"
ROLE_v2_2_0 = "v2_2_0"
# NOTE: don't forget to change version in check_stack_analyses_response()


class BlackduckLicenseDetails(jsl.Document):
    class Options:
        description = "Blackduck information about one license for a single component"
        definition_id = "component_blackduck_license_info"

    with removed_in(ROLE_v2_2_0) as removed_in_v2_2_0:
        removed_in_v2_2_0.codeSharing = jsl.StringField(required=True)
    with added_in(ROLE_v2_2_0) as added_in_v2_2_0:
        added_in_v2_2_0.code_sharing = jsl.StringField(required=True)
    name = jsl.StringField(required=True)


class BlackduckSecurityDetails(jsl.Document):
    class Options:
        description = "Blackduck information about one vulnerability for a single component"
        definition_id = "component_blackduck_security_info"

    with removed_in(ROLE_v2_2_0) as removed_in_v2_2_0:
        removed_in_v2_2_0.baseScore = jsl.NumberField(required=True)
        removed_in_v2_2_0.exploitabilitySubscore = jsl.NumberField(required=True)
    with added_in(ROLE_v2_2_0) as added_in_v2_2_0:
        added_in_v2_2_0.base_score = jsl.NumberField(required=True)
        added_in_v2_2_0.exploitability_subscore = jsl.NumberField(required=True)
    id = jsl.StringField(required=True)
    severity = jsl.StringField(required=True)
    source = jsl.StringField(required=True)


class BlackduckDetails(jsl.Document):
    class Options:
        description = "Blackduck information for a single component"
        definition_id = "component_blackduck_info"

    license = jsl.ArrayField(jsl.DocumentField(BlackduckLicenseDetails, as_ref=True))
    security = jsl.ArrayField(jsl.DocumentField(BlackduckSecurityDetails, as_ref=True))


class CVEDetail(jsl.Document):
    class Options:
        description = "Information about one CVE for a single component"
        definition_id = "component_cve_info"

    cvss = jsl.NumberField(required=True)
    id = jsl.StringField(required=True)


with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as v2_0_0:
    class Month(jsl.Document):
        class Options:
            description = "GitHub Last Month Metrics"
            definition_id = "github_last_month_metrics"
        opened = jsl.NumberField(required=True)
        closed = jsl.NumberField(required=True)

    class Year(jsl.Document):
        class Options:
            description = "GitHub Last Year Metrics"
            definition_id = "github_last_year_metrics"
        opened = jsl.NumberField(required=True)
        closed = jsl.NumberField(required=True)

    class GithubMetrics(jsl.Document):
        class Options:
            description = "GitHub Metrics"
            definition_id = "github_metrics"
        month = jsl.DocumentField(Month, as_ref=True, required=True)
        year = jsl.DocumentField(Year, as_ref=True, required=True)


class GithubDetails(jsl.Document):
    class Options:
        description = "Github information for a single component"
        definition_id = "component_github_info"

    forks_count = jsl.NumberField(required=True)
    stargazers_count = jsl.NumberField(required=True)
    with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as v2_0_0:
        v2_0_0.issues = jsl.DocumentField(GithubMetrics, as_ref=True, required=True)
        v2_0_0.pull_requests = jsl.DocumentField(GithubMetrics, as_ref=True, required=True)


with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as v2_0_0:
    class RegisteredSRPM(jsl.Document):
        class Options:
            description = "Red Hat internally registered SRPM details a single component"
            definition_id = "component_redhat_registered_srpms"

        patch_count = jsl.NumberField(required=True)
        epoch = jsl.NumberField(required=True)
        published_in = jsl.ArrayField(jsl.StringField(), required=True)
        modified_line_count = jsl.NumberField(required=True)
        package_name = jsl.StringField(required=True)
        modified_file_count = jsl.NumberField(required=True)
        version = jsl.StringField(required=True)
        release = jsl.StringField(required=True)

    class RedHatUsage(jsl.Document):
        class Options:
            description = "Red Hat internal usage information for a single component"
            definition_id = "component_redhat_usage"

        package_names = jsl.ArrayField(jsl.StringField(), required=True)
        published_in = jsl.ArrayField(jsl.StringField(), required=True)
        registered_srpms = jsl.ArrayField(jsl.DocumentField(RegisteredSRPM, as_ref=True),
                                          required=True)
        with added_in(ROLE_v2_1_1) as added_in_v2_1_1:
            added_in_v2_1_1.all_rhn_channels = jsl.ArrayField(jsl.StringField())
            added_in_v2_1_1.all_rhsm_content_sets = jsl.ArrayField(jsl.StringField())
        with added_in(ROLE_v2_1_2) as added_in_v2_1_2:
            added_in_v2_1_2.all_rhsm_product_names = jsl.ArrayField(jsl.StringField())
        with added_in(ROLE_v2_1_3) as added_in_v2_1_3:
            added_in_v2_1_3.rh_mvn_matched_versions = jsl.ArrayField(jsl.StringField())

    class Popularity(jsl.Document):
        class Options:
            description = "Stack popularity"
            definition_id = "stack_popularity"
        average_forks = jsl.StringField(required=True)
        average_stars = jsl.StringField(required=True)
        low_popularity_components = jsl.NumberField(required=True)

    class Usage(jsl.Document):
        class Options:
            description = "Stack usage"
            definition_id = "stack_usage"
        average_usage = jsl.StringField(required=True)
        low_public_usage_components = jsl.NumberField(required=True)
        redhat_distributed_components = jsl.NumberField(required=True)

with jsl.Scope(lambda v: v >= ROLE_v2_0_3) as added_in_v2_0_3:
    class ComponentMetadataEngines(jsl.Document):
        class Options:
            description = "Version of engine/interpreter/package manager"
            definition_id = "component_metadata_engines"
        name = jsl.StringField()
        version = jsl.StringField()

    class ComponentMetadata(jsl.Document):
        class Options:
            description = "Data from metadata file"
            definition_id = "component_metadata"
        tests_implemented = jsl.BooleanField()
        required_engines = jsl.DocumentField(ComponentMetadataEngines, as_ref=True, required=True)
        dependency_lock_file = jsl.BooleanField()


class ComponentInfo(jsl.Document):
    class Options:
        description = "Information about a single component"
        definition_id = "component_info"

    blackduck_details = jsl.DocumentField(BlackduckDetails, as_ref=True, required=True)
    cve_details = jsl.ArrayField(jsl.DocumentField(CVEDetail, as_ref=True), required=True)
    ecosystem = jsl.StringField(required=True)
    github_details = jsl.DocumentField(GithubDetails, as_ref=True, required=True)
    id = jsl.StringField(required=True)
    latest_version = jsl.OneOfField([jsl.StringField(), jsl.NullField()], required=True)
    licenses = jsl.ArrayField(jsl.StringField(), required=True)
    name = jsl.StringField(required=True)
    package_dependents_count = jsl.NumberField(required=True)
    version = jsl.StringField(required=True)

    with jsl.Scope(lambda v: v >= ROLE_v1_1_0) as added_in_v1_1_0:
        added_in_v1_1_0.dependents_count = jsl.NumberField(required=True)

    with jsl.Scope(lambda v: v >= ROLE_v1_2_0) as added_in_v1_2_0:
        added_in_v1_2_0.relative_usage = jsl.StringField(required=True)

    with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as added_in_v2_0_0:
        added_in_v2_0_0.redhat_usage = jsl.DocumentField(RedHatUsage, as_ref=True, required=True)

    with jsl.Scope(lambda v: v >= ROLE_v2_0_3) as added_in_v2_0_3:
        added_in_v2_0_3.metadata = jsl.DocumentField(ComponentMetadata, as_ref=True, required=True)


with jsl.Scope(lambda v: v >= ROLE_v2_0_2) as v2_0_2:
    class InputStack(jsl.Document):
        class Options:
            description = "Input stack for generating recommendations"
            definition_id = "input_stack"
        appstack_id = jsl.StringField(required=True)
        uri = jsl.StringField(required=True)

    class SimilarityAnalysis(jsl.Document):
        class Options:
            description = "Stack Similarity Analysis Result"
            definition_id = "stack_similarity_analysis"
        missing_packages = jsl.ArrayField(jsl.StringField(), required=True)
        version_mismatch = jsl.ArrayField(jsl.StringField(), required=True)
        with jsl.Scope(lambda v: v >= ROLE_v2_1_4) as v2_1_4:
            v2_1_4.missing_downstream_component = jsl.ArrayField(jsl.StringField(), required=True)

    class SimilarStacks(jsl.Document):
        class Options:
            description = "Stack Similarity Information"
            definition_id = "stack_similarity_information"
        analysis = jsl.DocumentField(SimilarityAnalysis, as_ref=True, required=True)
        similarity = jsl.NumberField(required=True)
        stack_id = jsl.NumberField(required=True)
        uri = jsl.StringField(required=True)
        with jsl.Scope(lambda v: v >= ROLE_v2_1_4) as v2_1_4:
            v2_1_4.source = jsl.StringField(required=True)
            v2_1_4.usage = jsl.NumberField(required=True)
            v2_1_4.original_score = jsl.NumberField(required=True)

    class StackRecommendations(jsl.Document):
        class Options:
            description = "Stack Recommendations"
            definition_id = "stack_recommendations"
        # TODO: Get more details about component_level. Current example
        # responses have this field as Null
        component_level = jsl.NullField(required=True)
        similar_stacks = jsl.ArrayField(jsl.DocumentField(SimilarStacks, as_ref=True),
                                        required=True)

    class Recommendation(jsl.Document):
        class Options:
            description = "Bayesian recommended stacks"
            definition_id = "recommended_stacks"
        input_stack = jsl.DocumentField(InputStack, as_ref=True, Required=True)
        recommendations = jsl.DocumentField(StackRecommendations, as_ref=True, Required=True)


with jsl.Scope(lambda v: v >= ROLE_v2_0_3) as added_in_v2_0_3:
    class Metadata(jsl.Document):
        class Options:
            description = "Data from metadata file"
            definition_id = "metadata"
        components_with_dependency_lock_file = jsl.NumberField(required=True)
        components_with_tests = jsl.NumberField(required=True)
        required_engines = jsl.DocumentField(ComponentMetadataEngines, as_ref=True, required=True)


class StackAnalysisReport(jsl.Document):
    class Options:
        description = "Stack analysis report with aggregated data"
        definition_id = "stack_analysis_report"

    with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as v2_0_0:
        v2_0_0.manifest_name = jsl.StringField(required=True)
        v2_0_0.ecosystem = jsl.StringField(required=True)
        v2_0_0.cvss = jsl.NumberField(required=True)
        v2_0_0.popularity = jsl.DocumentField(Popularity, as_ref=True, Required=True)
        v2_0_0.usage = jsl.DocumentField(Usage, as_ref=True, Required=True)
    with jsl.Scope(lambda v: v >= ROLE_v2_0_2) as v2_0_2:
        v2_0_2.recommendation = jsl.DocumentField(Recommendation, as_ref=True)
    with jsl.Scope(lambda v: v >= ROLE_v2_0_3) as added_in_v2_0_3:
        added_in_v2_0_3.metadata = jsl.DocumentField(Metadata, as_ref=True, required=True)

    analyzed_components = jsl.NumberField(required=True)
    total_security_issues = jsl.NumberField(required=True)
    total_licenses = jsl.NumberField(required=True)
    components_with_security_issues = jsl.ArrayField(jsl.StringField(), required=True)
    distinct_licenses = jsl.ArrayField(jsl.StringField(), required=True)
    components = jsl.ArrayField(jsl.DocumentField(ComponentInfo, as_ref=True), required=True)


class StackAnalysisResult(jsl.Document):
    class Options:
        description = "Stack analysis result"
        definition_id = "stack_analysis_result"

    stack_analyses = jsl.DocumentField(StackAnalysisReport, name="stack-analyses", as_ref=True)


class StackAnalysisResponse(JSLSchemaBase):
    class Options:
        description = "Stack analysis"
        definition_id = "stack_analysis"

    with jsl.Scope(lambda v: v < ROLE_v2_0_1) as before_v2_0_1:
        before_v2_0_1.status = jsl.StringField(enum=["FINISHED", "FAILED", "INPROGRESS"],
                                               required=True)
    with jsl.Scope(lambda v: v >= ROLE_v2_0_1) as since_v2_0_1:
        since_v2_0_1.status = jsl.StringField(enum=["success"], required=True)
    submitted_at = jsl.DateTimeField(required=True)
    started_at = jsl.DateTimeField(required=True)
    finished_at = jsl.DateTimeField(required=True)
    request_id = jsl.StringField(required=True)
    with jsl.Scope(lambda v: v < ROLE_v2_1_0) as removed_in_v2_1_0:
        removed_in_v2_1_0.analyses_result = jsl.ArrayField(jsl.StringField(), required=True)
    with jsl.Scope(lambda v: v == ROLE_v1_0_0 or v == ROLE_v1_1_0 or
                   v == ROLE_v1_2_0) as upto_v1_2_0:
        upto_v1_2_0.result = jsl.DocumentField(StackAnalysisResult, required=True)
    with jsl.Scope(lambda v: v >= ROLE_v2_0_0) as added_in_v2_0_0:
        added_in_v2_0_0.result = jsl.ArrayField(jsl.DocumentField(StackAnalysisReport,
                                                                  as_ref=True),
                                                required=True)


THE_SCHEMA = StackAnalysisResponse
