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

from requests import get, post, exceptions

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


def server_create_analysis(ecosystem, package, version, api_flow=True, force=False, force_graph_sync=False):
    """Create bayesianApiFlow handling analyses for specified EPV

    :param ecosystem: ecosystem for which the flow should be run
    :param package: package for which should be flow run
    :param version: package version
    :param force: force run flow even specified EPV exists
    :param force_graph_sync: force synchronization to graph
    :return: dispatcher ID handling flow
    """
    args = {
        'ecosystem': ecosystem,
        'name': MavenCoordinates.normalize_str(package) if ecosystem == 'maven' else package,
        'version': version,
        'force': force,
        'force_graph_sync': force_graph_sync
    }

    if api_flow:
        return server_run_flow('bayesianApiFlow', args)
    else:
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

def generate_recommendation(data, package, version):
    # Template Dict for recommendation
    reco = {
        'recommendation': {
            'component-analyses': {},
        }
    }
    if data:
        # Get the Latest Version
        latest_version = data[0].get('package', {}).get('latest_version', [None])[0]
        message = ''
        max_cvss = 0.0
        # check if given version has a CVE or not
        for records in data:
            ver = records['version']
            if version == ver.get('version', [''])[0]:
                records_arr = []
                records_arr.append(records)
                reco['data'] = records_arr
                cve_ids = []
                cve_maps = []
                if ver.get('cve_ids', [''])[0] != '':
                    message = 'CVE/s found for Package - ' + package + ', Version - ' + version + '\n'
                    # for each CVE get cve_id and cvss scores
                    for cve in ver.get('cve_ids'):
                        cve_id = cve.split(':')[0]
                        cve_ids.append(cve_id)
                        cvss = float(cve.split(':')[1])
                        cve_map = {
                            'id': cve_id,
                            'cvss': cvss
                        }
                        cve_maps.append(cve_map)
                        if cvss > max_cvss:
                            max_cvss = cvss
                    message += ', '.join(cve_ids)
                    message += ' with a max cvss score of - ' + str(max_cvss)
                    reco['recommendation']['component-analyses']['cve'] = cve_maps
                    break
                else:
                    reco['recommendation'] = {}
                    return {"result": reco}

        # check if latest version exists or current version is latest version
        if not latest_version or latest_version == '' or version == latest_version:
            if message != '':
                reco['recommendation']['message'] = message
            return {"result": reco}
        # check if latest version has lower CVEs or no CVEs than current version
        for records in data:
            ver = records['version']
            if latest_version == ver.get('version', [''])[0]:
                if ver.get('cve_ids', [''])[0] != '':
                    for cve in ver.get('cve_ids'):
                        cvss = float(cve.split(':')[1])
                        if cvss >= max_cvss:
                            break
                message += '\n It is recommended to use Version - ' + latest_version
                reco['recommendation']['change_to'] = latest_version
                reco['recommendation']['message'] = message
    return {"result": reco}


def search_packages_from_graph(tokens):
    # TODO remove hardcoded url when moving to Production This is just a stop-gap measure for demo
    url = "http://{host}:{port}".format \
          (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
           port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

    # TODO query string for actual STAGE/PROD
    # g.V().has('vertex_label','Package').has('tokens','one').has('tokens','two').
    # out('has_version').valueMap('pecosystem', 'pname', 'version')).limit(5)
    qstring = "g.V().has('vertex_label','Package')"
    # qstring = "g.V()"
    for tkn in tokens:
        if tkn:
            # TODO Change qstring
            qstring += ".has('tokens', '" + tkn + "')"
            # qstring += ".has('alias', '" + tkn + "')"

    # qstring += ".has('version').valueMap('pecosystem', 'pname', 'version').limit(5)"
    qstring += ".out('has_version').valueMap('pecosystem', 'pname', 'version').dedup().limit(5)"

    payload = {'gremlin': qstring}

    response = post(url, data=json.dumps(payload))
    resp = response.json()
    packages = resp.get('result', {}).get('data', [])
    if not packages:
        return json.dumps({'result': []})

    pkg_list = []
    for pkg in packages:
        condition = [pkg['pecosystem'][0] is not None, pkg['pname'][0] is not None, pkg['version'][0] is not None]
        if all(condition):
            pkg_map = {
                'ecosystem': pkg['pecosystem'][0],
                'name': pkg['pname'][0],
                'version': pkg['version'][0]
            }
            pkg_list.append(pkg_map)

    return json.dumps({'result': pkg_list})


def get_analyses_from_graph (ecosystem, package, version):
    url = "http://{host}:{port}".format\
            (host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),\
             port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))
    qstring = "g.V().has('ecosystem','" + ecosystem + "').has('name','" + package + "')" \
              ".as('package').out('has_version').as('version').select('package','version').by(valueMap());"
    payload = {'gremlin': qstring}
    try:
        graph_req = post(url, data=json.dumps(payload))
    except:
        return None

    resp = graph_req.json()

    if 'result' not in resp:
        return None
    if len(resp['result']['data']) == 0:
        # trigger unknown component flow in API for missing package
        return None

    data = resp['result']['data']
    resp = generate_recommendation(data, package, version)

    if 'data' not in resp.get('result'):
        # trigger unknown component flow in API for missing version
        return None

    return resp

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


def fetch_public_key(app):
    """ Gets public key and caches it on the app object for future use """
    # TODO: even though saving the key on the app object is not very nice,
    #  it's actually safe - the worst thing that can happen is that we will
    #  fetch and save the same value on the app object multiple times
    if not getattr(app, 'public_key', ''):
        keycloak_url = app.config.get('BAYESIAN_FETCH_PUBLIC_KEY', '')
        if keycloak_url:
            pub_key_url = keycloak_url.strip('/') + '/auth/realms/fabric8/'
            try:
                result = get(pub_key_url, timeout=0.5)
                app.logger.info('Fetching public key from %s, status %d, result: %s',
                                pub_key_url, result.status_code, result.text)
            except exceptions.Timeout:
                app.logger.error('Timeout fetching public key from %s', pub_key_url)
                return ''
            if result.status_code != 200:
                return ''
            pkey = result.json().get('public_key', '')
            app.public_key = \
                '-----BEGIN PUBLIC KEY-----\n{pkey}\n-----END PUBLIC KEY-----'.format(pkey=pkey)
        else:
            app.public_key = app.config.get('BAYESIAN_PUBLIC_KEY')

    return app.public_key

def retrieve_worker_result (rdb, external_request_id, worker):
    try:
        results = rdb.session.query(WorkerResult)\
                             .filter(WorkerResult.external_request_id == external_request_id,
                             WorkerResult.worker == worker)
        if results.count() <= 0:
            return None
    except SQLAlchemyError:
        return None

    result = {}
    for row in results:
        result = row.to_dict()
    return result

