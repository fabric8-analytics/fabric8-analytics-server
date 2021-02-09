"""Various utility functions."""

# TODO split this module into categories (graph DB, analyses etc.)

# Improve maintainability index
# TODO: https://github.com/fabric8-analytics/fabric8-analytics-server/issues/373

import datetime
import os
import uuid
import hashlib
import logging
from selinon import run_flow
from flask import current_app
from flask.json import JSONEncoder
import semantic_version as sv
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from f8a_worker.models import (WorkerResult, StackAnalysisRequest)
from f8a_worker.utils import json_serial, MavenCoordinates
from f8a_worker.setup_celery import init_celery
from .default_config import STACK_ANALYSIS_REQUEST_TIMEOUT
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

# TODO remove hardcoded gremlin_url when moving to Production This is just
#      a stop-gap measure for demo

gremlin_url = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

companion_reason_statement = "along with the provided input stack. " \
    "Do you want to consider adding this Package?"

zero_version = sv.Version("0.0.0")


def server_run_flow(flow_name, flow_args):
    """Run a flow.

    :param flow_name: name of flow to be run as stated in YAML config file
    :param flow_args: arguments for the flow
    :return: dispatcher ID handling flow
    """
    logger.debug('Running flow %s', flow_name)
    start = datetime.datetime.now()

    init_celery(result_backend=False)
    dispacher_id = run_flow(flow_name, flow_args)

    logger.debug('It took %f seconds to start %s flow.',
                 (datetime.datetime.now() - start).total_seconds(), flow_name)
    return dispacher_id


def get_user_email(user_profile):
    """Get user e-mail address or the default address if user profile does not exist."""
    # fallback address
    default_email = 'bayesian@redhat.com'
    if user_profile is not None:
        return user_profile.get('email', default_email)
    else:
        return default_email


def server_create_component_bookkeeping(ecosystem, name, version, user_profile):
    """Run the component analysis for given ecosystem+package+version."""
    args = {
        'external_request_id': uuid.uuid4().hex,
        'data': {
            'api_name': 'component_analyses',
            'user_email': get_user_email(user_profile),
            'user_profile': user_profile,
            'request': {'ecosystem': ecosystem, 'name': name, 'version': version}
        }
    }
    return server_run_flow('componentApiFlow', args)


def create_component_bookkeeping(ecosystem, packages_list,
                                 user_id, user_agent, manifest_hash, request_id):
    """Run the component analysis for given ecosystem+package+version."""
    args = {
        'data': {
            'api_name': 'component_analyses_post'
        },
        'external_request_id': request_id,
        'manifest_hash': hashlib.md5(manifest_hash.encode()).hexdigest(),
        'ecosystem': ecosystem,
        'packages_list': packages_list,
        'user_id': user_id,
        'user_agent': user_agent
    }
    return server_run_flow('componentApiFlow', args)


def server_create_analysis(ecosystem, package, version, user_profile,
                           api_flow=True, force=False, force_graph_sync=False):
    """Create bayesianApiFlow handling analyses for specified EPV.

    :param ecosystem: ecosystem for which the flow should be run
    :param package: package for which should be flow run
    :param version: package version
    :param force: force run flow even specified EPV exists
    :param force_graph_sync: force synchronization to graph
    :return: dispatcher ID handling flow
    """
    # Bookkeeping first
    component = MavenCoordinates.normalize_str(package) if ecosystem == 'maven' else package

    args = {
        'ecosystem': ecosystem,
        'name': component,
        'version': version,
        'force': force,
        'force_graph_sync': force_graph_sync
    }

    if api_flow:
        return server_run_flow('bayesianApiFlow', args)
    else:
        return server_run_flow('bayesianFlow', args)


def get_system_version():
    """Get the actual version of the server.

    It's usually set up from the F8A_SYSTEM_VERSION environment variable.
    """
    try:
        with open(current_app.config['SYSTEM_VERSION']) as f:
            lines = f.readlines()
    except OSError:
        raise

    ret = {}
    for line in lines:
        couple = line.strip().split(sep='=', maxsplit=1)
        if len(couple) > 1:
            ret[couple[0].lower()] = couple[1]
    return ret


class JSONEncoderWithExtraTypes(JSONEncoder):
    """JSON Encoder that supports additional types.

    - date/time objects
    - arbitrary non-mapping iterables
    """

    # TODO I already seen similar implementation elsewhere, probably a candidate for a package?
    def default(self, obj):
        """Implement the custom JSON encoder."""
        try:
            if isinstance(obj, datetime.datetime):
                return json_serial(obj)
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)


def retrieve_worker_result(rdb, external_request_id, worker):
    """Retrieve results for selected worker from RDB."""
    start = datetime.datetime.now()
    try:
        query = rdb.session.query(WorkerResult) \
                           .filter(WorkerResult.external_request_id == external_request_id,
                                   WorkerResult.worker == worker)
        result = query.one()
    except (NoResultFound, MultipleResultsFound):
        return None
    except SQLAlchemyError:
        rdb.session.rollback()
        raise
    result_dict = result.to_dict()

    # compute elapsed time
    logger.debug('%s took %f seconds to retrieve %s worker results.',
                 external_request_id, (datetime.datetime.now() - start).total_seconds(),
                 worker)

    return result_dict


def fetch_sa_request(rdb, external_request_id):
    """Query the stack analysis record for a given request id."""
    try:
        return rdb.session.query(StackAnalysisRequest)\
                          .filter(StackAnalysisRequest.id == external_request_id).first()
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


def request_timed_out(request):
    """Check if a stack analysis request has timed out."""
    row = request.to_dict()
    submit_time = row.get("submitTime", {})

    current_time = datetime.datetime.now()
    diff = (current_time - submit_time).seconds

    if diff > int(STACK_ANALYSIS_REQUEST_TIMEOUT):
        return True
    return False


def convert_version_to_proper_semantic(version, package_name=None):
    """Perform Semantic versioning.

    : type version: string
    : param version: The raw input version that needs to be converted.
    : type return: semantic_version.base.Version
    : return: The semantic version of raw input version.
    """
    conv_version = sv.Version.coerce('0.0.0')
    try:
        if version in ('', '-1', None):
            version = '0.0.0'
        """Needed for maven version like 1.5.2.RELEASE to be converted to
        1.5.2 - RELEASE for semantic version to work."""
        version = version.replace('.', '-', 3)
        version = version.replace('-', '.', 2)
        # Needed to add this so that -RELEASE is account as a Version.build
        version = version.replace('-', '+', 3)
        conv_version = sv.Version.coerce(version)
    except ValueError:
        logger.error('Unexpected ValueError for the package %s due to version %s',
                     package_name, version)
        pass
    finally:
        return conv_version


def version_info_tuple(version):
    """Return version information in form of (major, minor, patch, build) for a given sem Version.

    : type version: semantic_version.base.Version
    : param version: The semantic version whole details are needed.
    : return: A tuple in form of Version.(major, minor, patch, build)
    """
    if type(version) == sv.base.Version:
        return(version.major,
               version.minor,
               version.patch,
               version.build)
    return (0, 0, 0, tuple())


def is_valid(param):
    """Return true is the param is not a null value."""
    return param is not None


def generate_content_hash(content):
    """Return the sha1 digest of a string."""
    hash_object = hashlib.sha1(content.encode('utf-8'))
    return hash_object.hexdigest()


# TODO: this is module constant -> use capital letters with underscores separating words.
accepted_file_names = {
        "npmlist.json": "npm",
        "golist.json": "golang",
        "pylist.json": "pypi",
        "dependencies.txt": "maven"
}


accepted_ecosystems = [
    "npm",
    "maven",
    "pypi",
    "golang",
]


def check_for_accepted_ecosystem(ecosystem):
    """Check if the ecosystem is supported or not."""
    return ecosystem in accepted_ecosystems


def resolved_files_exist(manifests):
    """Check if the manifest files are already resolved."""
    if type(manifests) is list:
        for manifest in manifests:
            if manifest['filename'] in accepted_file_names:
                return True
    else:
        if manifests in accepted_file_names:
            return True
    return False


def get_ecosystem_from_manifest(manifests):
    """Check if the manifest files are already resolved."""
    if type(manifests) is list:
        for manifest in manifests:
            if manifest['filename'] in accepted_file_names:
                return accepted_file_names[manifest['filename']]
    else:
        if manifests in accepted_file_names:
            return accepted_file_names[manifests]
    return None
