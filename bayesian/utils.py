import datetime
import json
import os
import uuid
import shutil

from selinon import run_flow
from flask import current_app
from flask.json import JSONEncoder
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from urllib.parse import urljoin

from f8a_worker.models import (Analysis, Ecosystem, Package, Version,
                               WorkerResult, StackAnalysisRequest)
from f8a_worker.utils import json_serial, MavenCoordinates, parse_gh_repo
from f8a_worker.process import Git
from f8a_worker.setup_celery import init_celery


from . import rdb
from .exceptions import HTTPError
from .default_config import BAYESIAN_COMPONENT_TAGGED_COUNT

from requests import get, post, exceptions
from sqlalchemy.exc import SQLAlchemyError

# TODO remove hardcoded gremlin_url when moving to Production This is just
#      a stop-gap measure for demo

gremlin_url = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))


def get_recent_analyses(limit=100):
    return rdb.session.query(Analysis).order_by(
        Analysis.started_at.desc()).limit(limit)


def server_run_flow(flow_name, flow_args):
    """Run a flow

    :param flow_name: name of flow to be run as stated in YAML config file
    :param flow_args: arguments for the flow
    :return: dispatcher ID handling flow
    """
    current_app.logger.debug('Running flow {}'.format(flow_name))
    start = datetime.datetime.now()

    init_celery(result_backend=False)
    dispacher_id = run_flow(flow_name, flow_args)

    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    current_app.logger.debug("It took {t} seconds to start {f} flow.".format(
        t=elapsed_seconds, f=flow_name))
    return dispacher_id


def get_user_email(user_profile):
    default_email = 'bayesian@redhat.com'
    if user_profile is not None:
        return user_profile.get('email', default_email)
    else:
        return default_email


def server_create_component_bookkeeping(ecosystem, name, version, user_profile):
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


def server_create_analysis(ecosystem, package, version, user_profile,
                           api_flow=True, force=False, force_graph_sync=False):
    """Create bayesianApiFlow handling analyses for specified EPV

    :param ecosystem: ecosystem for which the flow should be run
    :param package: package for which should be flow run
    :param version: package version
    :param force: force run flow even specified EPV exists
    :param force_graph_sync: force synchronization to graph
    :return: dispatcher ID handling flow
    """
    # Bookkeeping first
    component = MavenCoordinates.normalize_str(package) if ecosystem == 'maven' else package
    server_create_component_bookkeeping(ecosystem, component, version, user_profile)

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


def do_projection(fields, analysis):
    """Return filtered dictionary containing model data"""
    if fields is None or analysis is None:
        try:
            return analysis.to_dict()
        except Exception:
            return None
    analysis = analysis.to_dict()

    ret = {}
    for f in fields:
        field = f.split('.')
        if has_field(analysis, field):
            add_field(analysis, field, ret)
    return ret


def has_field(analysis, fields):
    """Return true or false if given field exists in analysis"""
    for field in fields:
        try:
            analysis = analysis[field]
        except Exception:
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
                    message = 'CVE/s found for Package - ' + package + ', Version - ' + \
                              version + '\n'
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
    # TODO query string for actual STAGE/PROD
    # g.V().has('vertex_label','Package').has('tokens','one').has('tokens','two').
    # out('has_version').valueMap('pecosystem', 'pname', 'version')).limit(5)
    qstring = "g.V()"
    # qstring = "g.V()"
    for tkn in tokens:
        if tkn:
            # TODO Change qstring
            qstring += ".has('tokens', '" + tkn + "')"
            # qstring += ".has('alias', '" + tkn + "')"

    # qstring += ".has('version').valueMap('pecosystem', 'pname', 'version').limit(5)"
    qstring += ".out('has_version').valueMap('pecosystem', 'pname', 'version').dedup().limit(5)"

    payload = {'gremlin': qstring}

    response = post(gremlin_url, data=json.dumps(payload))
    resp = response.json()
    packages = resp.get('result', {}).get('data', [])
    if not packages:
        return {'result': []}

    pkg_list = []
    for pkg in packages:
        condition = [pkg['pecosystem'][0] is not None,
                     pkg['pname'][0] is not None,
                     pkg['version'][0] is not None]
        if all(condition):
            pkg_map = {
                'ecosystem': pkg['pecosystem'][0],
                'name': pkg['pname'][0],
                'version': pkg['version'][0]
            }
            pkg_list.append(pkg_map)

    return {'result': pkg_list}


def get_analyses_from_graph(ecosystem, package, version):
    qstring = "g.V().has('ecosystem','" + ecosystem + "').has('name','" + package + "')" \
              ".as('package').out('has_version').as('version').select('package','version')." \
              "by(valueMap());"
    payload = {'gremlin': qstring}
    start = datetime.datetime.now()
    try:
        graph_req = post(gremlin_url, data=json.dumps(payload))
    except Exception as e:
        current_app.logger.debug(' '.join([type(e), ':', str(e)]))
        return None
    finally:
        elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
        epv = "{e}/{p}/{v}".format(e=ecosystem, p=package, v=version)
        current_app.logger.debug("Gremlin request {p} took {t} seconds.".format(p=epv,
                                                                                t=elapsed_seconds))

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
    if ecosystem == 'maven':
        package = MavenCoordinates.normalize_str(package)
    try:
        return rdb.session.query(Analysis).\
            join(Version).join(Package).join(Ecosystem).\
            filter(Ecosystem.name == ecosystem).\
            filter(Package.name == package).\
            filter(Version.identifier == version).\
            order_by(Analysis.started_at.desc()).\
            first()
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


def get_latest_analysis_by_hash(algorithm, artifact_hash, projection=None):
    """Note: has to be called inside flask request context"""
    if algorithm not in ['sha1', 'sha256', 'md5']:
        return None

    contains_dict = {'details': [{"artifact": True, algorithm: artifact_hash}]}
    try:
        return rdb.session.query(Analysis).\
            join(WorkerResult).\
            filter(WorkerResult.worker == 'digests').\
            filter(WorkerResult.task_result.contains(contains_dict)).\
            order_by(Analysis.started_at.desc()).\
            first()
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


def get_system_version():
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


def build_nested_schema_dict(schema_dict):
    """Accepts a dictionary in form of {SchemaRef(): schema} and returns
    dictionary in form of {schema_name: {schema_version: schema}}
    """
    result = {}
    for schema_ref, schema in schema_dict.items():
        result.setdefault(schema_ref.name, {})
        result[schema_ref.name][schema_ref.version] = schema
    return result


def get_next_component_from_graph(ecosystem, user_id, company):
    qstring = ("user = g.V().has('userid','{uid}').tryNext().orElseGet{{graph.addVertex("
               "'vertex_label', 'User', 'userid', '{uid}' {company})}};"
               "g.V(user).as('u').V().has('ecosystem','{e}').has('manual_tagging_required', true)"
               ".has('tags_count', not(within({tc}))).coalesce(inE('has_tagged').as('pkg').outV()"
               ".as('b').where('u', neq('b')).outE('has_tagged').inV().as('np').where('pkg',"
               " neq('np')), V().has('ecosystem','{e}').has('manual_tagging_required', true)"
               ".not(inE('has_tagged'))).limit(1).valueMap();"
               .format(
                   uid=user_id,
                   e=ecosystem,
                   tc=int(BAYESIAN_COMPONENT_TAGGED_COUNT),
                   company=['', ", 'company', '{}'".format(company)][bool(company)]
               ))
    payload = {'gremlin': qstring}
    start = datetime.datetime.now()
    try:
        graph_req = post(gremlin_url, data=json.dumps(payload))
    except Exception as e:
        current_app.logger.debug(' '.join([type(e), ':', str(e)]))
        return None
    finally:
        elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
        current_app.logger.debug("Gremlin request for next component for"
                                 " ecosystem {e} took {t} seconds."
                                 .format(e=ecosystem, t=elapsed_seconds))

    resp = graph_req.json()

    if 'result' not in resp or 'data' not in resp.get('result'):
        return None
    if len(resp['result']['data']) == 0:
        return None

    pkg = resp['result']['data'][0].get('name')
    return pkg


def set_tags_to_component(ecosystem, package, tags, user_id, company):
    qstring = ("user = g.V().has('userid','{user_id}').tryNext().orElseGet{{graph.addVertex("
               "'vertex_label', 'User', 'userid', '{user_id}' {company})}};pkg = g.V().has('name'"
               ",'{package}').has('ecosystem','{ecosystem}').next();g.V(pkg).choose("
               "has('tags_count'),sack(assign).by('tags_count').sack(sum).by(constant(1)).property"
               "('tags_count', sack()), property('tags_count', 1)).property('user_tags', '{tags}')"
               ".iterate(); g.V(user).outE('has_tagged').outV().has('name','{package}').has("
               "'ecosystem','{ecosystem}').tryNext().orElseGet{{user.addEdge('has_tagged', pkg)}};"
               .format(
                   ecosystem=ecosystem,
                   package=package,
                   tags=';'.join(tags),
                   user_id=user_id,
                   company=['', ", 'company', '{}'".format(company)][bool(company)]
               ))

    payload = {'gremlin': qstring}
    start = datetime.datetime.now()
    try:
        post(gremlin_url, data=json.dumps(payload))
    except Exception as e:
        return False, ' '.join([type(e), ':', str(e)])
    finally:
        elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
        current_app.logger.debug(("Gremlin request for setting tags to component for ecosystem"
                                  " {e} took {t} seconds."
                                  .format(e=ecosystem, t=elapsed_seconds)))
    return True, None


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


def retrieve_worker_results(rdb, external_request_id):
    start = datetime.datetime.now()
    try:
        query = rdb.session.query(WorkerResult) \
                           .filter(WorkerResult.external_request_id == external_request_id)
        results = query.all()
    except (NoResultFound, MultipleResultsFound):
        return None
    except SQLAlchemyError:
        rdb.session.rollback()
        raise

    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    msg = "It took {t} seconds to retrieve " \
          "all worker results for {r}.".format(t=elapsed_seconds, r=external_request_id)
    current_app.logger.debug(msg)

    return results


def retrieve_worker_result(rdb, external_request_id, worker):
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
    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    msg = "It took {t} seconds to retrieve {w} " \
          "worker results for {r}.".format(t=elapsed_seconds, w=worker, r=external_request_id)
    current_app.logger.debug(msg)

    return result_dict


def get_item_from_list_by_key_value(items, key, value):
    for item in items:
        if item[key] == value:
            return item
    return None


def get_request_count(rdb, external_request_id):
    try:
        return rdb.session.query(StackAnalysisRequest)\
                          .filter(StackAnalysisRequest.id == external_request_id).count()
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


class GithubRead:
    CLONED_DIR = "/tmp/stack-analyses-repo-folder"
    PREFIX_GIT_URL = "https://github.com/"
    PREFIX_URL = "https://api.github.com/repos/"
    RAW_FIRST_URL = "https://raw.githubusercontent.com/"
    MANIFEST_TYPES = ["pom.xml", "package.json", "requirements.txt"]

    def get_manifest_files(self):
        manifest_file_paths = []
        for base, dirs, files in os.walk(self.CLONED_DIR):
            if '.git' in dirs:
                dirs.remove('.git')
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            for filename in files:
                if filename in self.MANIFEST_TYPES:
                    filepath = os.path.join(base, filename)
                    manifest_file_paths.append({
                        "filename": filename,
                        "filepath": filepath
                    })
        return manifest_file_paths

    def get_files_github_url(self, github_url):
        manifest_data = []
        repo_suffix = parse_gh_repo(github_url)
        try:
            self.del_temp_files()
            repo_url = urljoin(self.PREFIX_URL, repo_suffix)
            check_valid_repo = get(repo_url)
            if check_valid_repo.status_code == 200:
                repo_clone_url = urljoin(self.PREFIX_GIT_URL, repo_suffix, '.git')
                Git.clone(repo_clone_url, self.CLONED_DIR)
                for file_obj in self.get_manifest_files():
                    file_content = None
                    filename = file_obj.get('filename')
                    filepath = file_obj.get('filepath')
                    with open(filepath, 'rb') as m_file:
                        file_content = m_file.read().decode('utf-8')
                    manifest_data.append({
                        "filename": filename,
                        "content": file_content,
                        "filepath": filepath.replace(self.CLONED_DIR, '')
                    })
        except Exception as e:
            raise HTTPError(500, "Error in reading repo from github.")
        finally:
            self.del_temp_files()

        return manifest_data

    def del_temp_files(self):
        if os.path.exists(self.CLONED_DIR):
            shutil.rmtree(self.CLONED_DIR)


class RecommendationReason:
    """
    This is used to provide the reason for alternate, and companion package recommendations.
    """

    def add_reco_reason(self, manifest_response):
        """
        It will populate english sentence for the recommendations.
        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons
        """
        # Populate reason for each companion package
        if len(manifest_response[0].get("recommendation", {}).get("companion", [])) > 0:
            manifest_response = self._companion_reason(manifest_response)

        # Populate reason for each alternate package
        if len(manifest_response[0].get("recommendation", {}).get("alternate", [])) > 0:
            manifest_response = self._alternate_reason(manifest_response)
        return manifest_response

    def _alternate_reason(self, manifest_response):
        """
        It will populate simple reason for each alternate package recommendation
        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons for alternate package
        """
        for pkg in manifest_response[0].get("recommendation", {}).get("alternate", []):
            name = pkg.get("name")
            replaces = pkg.get("replaces", [])[0].get("name")
            test_usage_outlier = self._check_usage_outlier(replaces, manifest_response)
            sentence = ""
            if test_usage_outlier:
                sentence = "Package {} is recommended as an alternative for Package {} as it is " \
                           "comparatively used more with the given combination of input stack." \
                           "Do you want to consider replacing this Package?".format(name, replaces)
            pkg["reason"] = sentence
        return manifest_response

    def _check_usage_outlier(self, pkg_name, manifest_response):
        """
        It will check usage outlier a package mentioned by count index
        :param pkg_name: Name of the possible usage-outlier package
        :param manifest_response: dict. object having all recommendation elements
        :return: True or False for usage outlier of input package at count index position
        """
        test = False
        outliers = manifest_response[0].get("recommendation", {}).get("usage_outliers", [])
        if outliers:
            for outlier in outliers:
                if pkg_name == outlier.get("package_name"):
                    test = True
                    break
        return test

    def _companion_reason(self, manifest_response):
        """
        It will populate the simple reason for each companion package
        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons for each companion package
        """
        for pkg in manifest_response[0].get("recommendation", {}).get("companion", []):
            name = pkg.get("name")
            stack_count = str(pkg.get("cooccurrence_probability"))
            sentence = "Package {} appears in {} different stacks along with the provided input " \
                       "stack. Do you want to consider adding this Package?"\
                .format(name, stack_count)
            pkg["reason"] = sentence
        return manifest_response
