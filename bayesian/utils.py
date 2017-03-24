import datetime
import json
import os

from selinon import run_flow
from flask import current_app
from flask.json import JSONEncoder
from sqlalchemy.orm.exc import NoResultFound

from cucoslib.models import Analysis, Ecosystem, Package, Version, WorkerResult
from cucoslib.utils import json_serial, MavenCoordinates

from . import rdb
from .setup import Setup

from requests import post

def get_recent_analyses(limit=100):
    return rdb.session.query(Analysis).order_by(Analysis.started_at.desc()).limit(limit)


def server_run_flow(flow_name, flow_args):
    """Run a flow

    :param flow_name: name of flow to be run as stated in YAML config file
    :param flow_args: arguments for the flow
    :return: dispatcher ID handling flow
    """
    # Before we schedule a flow, we have to ensure that we are connected to broker
    Setup.connect_if_not_connected()
    return run_flow(flow_name, flow_args)


def server_create_analysis(ecosystem, package, version, force=False):
    """Create bayesianFlow handling analyses for specified EPV

    :param ecosystem: ecosystem for which the flow should be run
    :param package: package for which should be flow run
    :param version: package version
    :param force: force run flow even specified EPV exists
    :return: dispatcher ID handling flow
    """
    args = {
        'ecosystem': ecosystem,
        'name': MavenCoordinates.normalize_str(package) if ecosystem == 'maven' else package,
        'version': version,
        'force': force
    }

    return server_run_flow('bayesianFlow', args)


def do_projection(fields, analysis):
    """Return filtered dictionary containing model data"""
    if fields is None or analysis is None:
        try:
            return analysis.to_dict()
        except:
            return None
    analysis = analysis.to_dict()

    ret = {}
    for f in fields:
        field = f.split('.')
        if has_field(analysis, field):
            add_field(analysis, field, ret)
    return ret


def has_field(analysis, field):
    """Return true or false if given field exists in analysis"""
    for f in field:
        try:
            analysis = analysis[f]
        except:
            return False
    return True


def add_field(analysis, field, ret):
    """Adds field from analysis into final dictionary"""
    for f in field:
        analysis = analysis[f]
        prev_ret = ret
        ret = ret.setdefault(f, {})
    prev_ret[f] = analysis

def get_analyses_from_graph (ecosystem, package, version):
    url = "http://{host}:{port}".format\
            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
            port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
    qstring =  "g.V().has('pecosystem','"+ecosystem+"').has('pname','"+package+"').has('version','"+version+"')."
    qstring += "as('version').in('has_version').as('package').select('version','package').by(valueMap());"
    payload = {'gremlin': qstring}

    graph_req = post(url,data=json.dumps(payload))
    return {"result": graph_req.json()}

def get_latest_analysis_for(ecosystem, package, version):
    """Note: has to be called inside flask request context"""
    try:
        if ecosystem == 'maven':
            package = MavenCoordinates.normalize_str(package)
        return rdb.session.query(Analysis).\
            join(Version).join(Package).join(Ecosystem).\
            filter(Ecosystem.name == ecosystem).\
            filter(Package.name == package).\
            filter(Version.identifier == version).\
            order_by(Analysis.started_at.desc()).\
            first()
    except NoResultFound:
        return None


def get_latest_analysis_by_hash(algorithm, artifact_hash, projection=None):
    """Note: has to be called inside flask request context"""
    if algorithm not in ['sha1', 'sha256', 'md5']:
        return None

    try:
        contains_dict = {'details': [{"artifact": True, algorithm: artifact_hash}]}
        return rdb.session.query(Analysis).\
            join(WorkerResult).\
            filter(WorkerResult.worker == 'digests').\
            filter(WorkerResult.task_result.contains(contains_dict)).\
            order_by(Analysis.started_at.desc()).\
            first()
    except NoResultFound:
        return None


def get_system_version():
    try:
        with open(current_app.config['SYSTEM_VERSION']) as f:
            lines = f.readlines()
    except OSError:
        raise
        return {}

    ret = {}
    for line in lines:
        couple = line.strip().split(sep='=', maxsplit=1)
        if len(couple) > 1:
            ret[couple[0].lower()] = couple[1]
    return ret


def build_nested_schema_dict(schema_dict):
    """Accepts a dictionary in form of {SchemaRef(): schema} and returns
    dictionary in form of {schema_name: {schema_version: schema}}
    """
    result = {}
    for schema_ref, schema in schema_dict.items():
        result.setdefault(schema_ref.name, {})
        result[schema_ref.name][schema_ref.version] = schema
    return result


class JSONEncoderWithExtraTypes(JSONEncoder):
    """JSON Encoder that supports additional types:

        - date/time objects
        - arbitrary non-mapping iterables
    """
    def default(self, obj):
        try:
            if isinstance(obj, datetime.datetime):
                return json_serial(obj)
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)
