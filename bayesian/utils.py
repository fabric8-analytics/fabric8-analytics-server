"""Various utility functions."""

# TODO split this module into categories (graph DB, analyses etc.)

import datetime
import json
import os
import uuid
import shutil
import hashlib

from selinon import run_flow
from lru import lru_cache_function
from flask import current_app
from flask.json import JSONEncoder
import semantic_version as sv
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from urllib.parse import urljoin
from .default_config import CORE_DEPENDENCIES_REPO_URL

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
from github import Github, BadCredentialsException, GithubException, RateLimitExceededException

# TODO remove hardcoded gremlin_url when moving to Production This is just
#      a stop-gap measure for demo

gremlin_url = "http://{host}:{port}".format(
    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

companion_reason_statement = "along with the provided input stack. " \
    "Do you want to consider adding this Package?"

zero_version = sv.Version("0.0.0")


def get_recent_analyses(limit=100):
    """Get the recent analyses up to the specified limit."""
    return rdb.session.query(Analysis).order_by(
        Analysis.started_at.desc()).limit(limit)


def server_run_flow(flow_name, flow_args):
    """Run a flow.

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
    """Get user e-mail address or the default address if user profile does not exist."""
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
    """Return filtered dictionary containing model data."""
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
    """Return true or false if given field exists in analysis."""
    for field in fields:
        try:
            analysis = analysis[field]
        except Exception:
            return False
    return True


def add_field(analysis, field, ret):
    """Add field from analysis into final dictionary."""
    for f in field:
        analysis = analysis[f]
        prev_ret = ret
        ret = ret.setdefault(f, {})
    prev_ret[f] = analysis


def generate_recommendation(data, package, input_version):
    """Generate recommendation for the package+version."""
    # TODO: reduce cyclomatic complexity
    ip_ver_tuple = version_info_tuple(
        convert_version_to_proper_semantic(input_version))
    # Template Dict for recommendation
    reco = {
        'recommendation': {
            'component-analyses': {},
        }
    }
    if data:
        message = ''
        max_cvss = 0.0
        higher_version = ''
        # check if given version has a CVE or not
        for records in data:
            ver = records['version']
            if input_version == ver.get('version', [''])[0]:
                records_arr = []
                records_arr.append(records)
                reco['data'] = records_arr
                cve_ids = []
                cve_maps = []
                if ver.get('cve_ids', [''])[0] != '':
                    message = 'CVE/s found for Package - ' + package + ', Version - ' + \
                              input_version + '\n'
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

        for records in data:
            ver = records['version']
            graph_version = convert_version_to_proper_semantic(
                ver.get('version', [''])[0])
            graph_ver_tuple = version_info_tuple(graph_version)

            # Check for next best higher version than input version without any
            # CVE's
            if not ver.get('cve_ids') \
                    and graph_ver_tuple \
                    > ip_ver_tuple:
                if not higher_version:
                    higher_version = graph_version
                if version_info_tuple(higher_version) \
                        > graph_ver_tuple:
                    higher_version = graph_version

                recommendation_message = '\n It is recommended to use Version - ' + \
                    str(higher_version)
                reco['recommendation']['change_to'] = str(higher_version)
                reco['recommendation']['message'] = message + \
                    recommendation_message
    return {"result": reco}


def search_packages_from_graph(tokens):
    """Search for the package in the graph database."""
    # TODO query string for actual STAGE/PROD
    # g.V().has('vertex_label','Package').has('tokens','one').has('tokens','two').
    # out('has_version').valueMap('pecosystem', 'pname', 'version')).limit(5)
    qstring = ["g.V()"]
    tkn_string = ".has('tokens', '{t}' )"
    for tkn in tokens:
        if tkn:
            # TODO Change qstring
            qstring.append(tkn_string.format(t=tkn))

    qstring.append(".valueMap('ecosystem', 'name', 'libio_latest_version', 'latest_version')"
                   ".dedup().limit(5)")

    payload = {'gremlin': ''.join(qstring)}

    response = post(gremlin_url, data=json.dumps(payload))
    resp = response.json()
    packages = resp.get('result', {}).get('data', [])
    if not packages:
        return {'result': []}

    pkg_list = []
    for pkg in packages:
        eco = pkg.get('ecosystem', [''])[0]
        name = pkg.get('name', [''])[0]
        version = select_latest_version(
            pkg.get('latest_version', [''])[0],
            pkg.get('libio_latest_version', [''])[0],
            name)
        if all((eco, name, version)):
            pkg_map = {
                'ecosystem': eco,
                'name': name,
                'version': version
            }
            pkg_list.append(pkg_map)

    return {'result': pkg_list}


def get_analyses_from_graph(ecosystem, package, version):
    """Read analysis for given package+version from the graph database."""
    qstring = "g.V().has('ecosystem','" + ecosystem + "').has('name','" + package + "')" \
              ".as('package').out('has_version').as('version').dedup()." \
              "select('package', 'version').by(valueMap());"
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
    """Note: has to be called inside flask request context."""
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
    """Note: has to be called inside flask request context."""
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


def build_nested_schema_dict(schema_dict):
    """Accept a dictionary in form of {SchemaRef(): schema}.

    Return a dictionary in form of {schema_name: {schema_version: schema}}
    """
    result = {}
    for schema_ref, schema in schema_dict.items():
        result.setdefault(schema_ref.name, {})
        result[schema_ref.name][schema_ref.version] = schema
    return result


def get_next_component_from_graph(ecosystem, user_id, company):
    """Read next component from graph database."""
    # TODO it definitely needs to be refactored
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
    """Set tags to given package stored in the graph database."""
    # TODO it needs to be refactored
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


def fetch_public_key(app):
    """Get public key and caches it on the app object for future use."""
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
    """Retrieve results for all workers from RDB."""
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
    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    msg = "It took {t} seconds to retrieve {w} " \
          "worker results for {r}.".format(t=elapsed_seconds, w=worker, r=external_request_id)
    current_app.logger.debug(msg)

    return result_dict


def get_item_from_list_by_key_value(items, key, value):
    """Get the item from list containing sequence of dicts."""
    for item in items:
        if item[key] == value:
            return item
    return None


def get_request_count(rdb, external_request_id):
    """Query number of stack analysis requests for given request id."""
    try:
        return rdb.session.query(StackAnalysisRequest)\
                          .filter(StackAnalysisRequest.id == external_request_id).count()
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


class GithubRead:
    """Class with methods to read information about the package from GitHub."""

    # TODO move into its own module
    CLONED_DIR = "/tmp/stack-analyses-repo-folder"
    PREFIX_GIT_URL = "https://github.com/"
    PREFIX_URL = "https://api.github.com/repos/"
    RAW_FIRST_URL = "https://raw.githubusercontent.com/"
    MANIFEST_TYPES = ["pom.xml", "package.json", "requirements.txt"]

    def get_manifest_files(self):
        """Retrieve manifest files from cloned repository."""
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
        """Clone the repository from GitHub and retrieve manifest files from it."""
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
        """Delete temporary files in the CLONED_DIR repository."""
        if os.path.exists(self.CLONED_DIR):
            shutil.rmtree(self.CLONED_DIR)


class RecommendationReason:
    """Provide the reason for alternate, and companion package recommendations."""

    def add_reco_reason(self, manifest_response):
        """Populate a English sentence for the recommendations.

        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons
        """
        # Populate reason for each companion package
        for idx, manifest in enumerate(manifest_response):
            if not manifest.get('recommendation'):
                continue
            if len(manifest.get("recommendation", {}).get("companion", [])) > 0:
                manifest_response[idx] = self._companion_reason(manifest)

            # Populate reason for each alternate package
            if len(manifest.get("recommendation", {}).get("alternate", [])) > 0:
                manifest_response[idx] = self._alternate_reason(manifest)

        return manifest_response

    def _alternate_reason(self, manifest_response):
        """Populate simple reason for each alternate package recommendation.

        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons for alternate package
        """
        for pkg in manifest_response.get("recommendation", {}).get("alternate", []):
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
        """Check usage outlier a package mentioned by count index.

        :param pkg_name: Name of the possible usage-outlier package
        :param manifest_response: dict. object having all recommendation elements
        :return: True or False for usage outlier of input package at count index position
        """
        test = False
        outliers = manifest_response.get("recommendation", {}).get("usage_outliers", [])
        if outliers:
            for outlier in outliers:
                if pkg_name == outlier.get("package_name"):
                    test = True
                    break
        return test

    def _companion_reason(self, manifest_response):
        """Populate the simple reason for each companion package.

        :param manifest_response: dict. object having all recommendation elements
        :return: same dict. object with populated reasons for each companion package
        """
        for pkg in manifest_response.get("recommendation", {}).get("companion", []):
            count_sentence = None
            name = pkg.get("name")
            stack_confidence = pkg.get("cooccurrence_probability")
            stack_count = pkg.get("cooccurrence_count")
            if stack_confidence is None:
                """
                Log the value of zero confidence, so that it can be matched
                against Kronos output for validation.
                This should track any future occurence of this[1] error:
                Error:https://github.com/openshiftio/openshift.io/issues/2167
                """
                current_app.logger.error(
                    "Stack Count for {} when confidence=None is {}".format(name, stack_count))

            # 0% confidence is as good as not showing it on the UI.
            if stack_confidence == 0:
                stack_confidence = None

            # If stack_count is 0 or None, then do not generate the reason.
            if stack_count:
                count_sentence = "Package {} appears in {} different stacks ".format(
                    name, str(stack_count))
                count_sentence += companion_reason_statement
            pkg["confidence_reason"] = stack_confidence
            # Count reason
            pkg["reason"] = count_sentence
        return manifest_response


def get_cve_data(input_json):
    """Get CVEs for list of packages."""
    ecosystem = input_json.get('ecosystem')
    req_id = input_json.get('request_id')
    deps = input_json.get('_resolved', [])

    pkg_list = [itm['package'] for itm in deps]
    ver_list = [itm['version'] for itm in deps]

    str_gremlin = "g.V().has('pecosystem','" + ecosystem + "').has('pname', within(pkg_list))." \
                  "has('version', within(ver_list)).has('cve_ids')." \
                  "valueMap('pecosystem', 'pname', 'version', 'cve_ids');"

    payload = {
        'gremlin': str_gremlin,
        'bindings': {
            'ecosystem': ecosystem,
            'pkg_list': pkg_list,
            'ver_list': ver_list
        }
    }

    resp = post(gremlin_url, json=payload)
    jsn = resp.json()

    data = jsn.get('result', {}).get('data', [])

    result = []
    highest_stack_cvss = -1
    for itm in deps:
        cve_dict = {
            'ecosystem': ecosystem,
            'package': itm['package'],
            'version': itm['version'],
            'cve': None
        }
        # if there is any EPV with CVE, modify the cve details
        if data:
            for cve_itm in data:
                conditions = [ecosystem == cve_itm['pecosystem'][0],
                              itm['package'] == cve_itm['pname'][0],
                              itm['version'] == cve_itm['version'][0]]
                if all(conditions):
                    details = []
                    highest_cvss = -1
                    for cve in cve_itm['cve_ids']:
                        id, cvss = cve.split(':')
                        highest_cvss = max(float(cvss), highest_cvss)
                        highest_stack_cvss = max(highest_stack_cvss, highest_cvss)
                        details.append({
                            'cve_id': id,
                            'cvss': cvss
                        })
                    cve_dict['cve'] = {
                        'highest_cvss': highest_cvss,
                        'details': details
                    }

        result.append(cve_dict)

    return {
        "request_id": req_id,
        "result": result,
        "stack_highest_cvss": highest_stack_cvss
    }


def get_categories_data(runtime):
    """Get categories for based on runtime."""
    qstring = "g.V().has('category_runtime', runtime).as('category')."\
        "in('belongs_to_category').as('package').select('category', 'package').by(valueMap());"

    payload = {
        'gremlin': qstring,
        'bindings': {
            'runtime': runtime
        }
    }
    resp = post(gremlin_url, json=payload)
    return resp.json()


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
        current_app.logger.info(
            "Unexpected ValueError for the package {} due to version {}"
            .format(package_name, version))
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


def select_latest_version(latest='', libio='', package_name=None):
    """Retruns the latest version among current latest version and libio version."""
    return_version = ''
    latest_sem_version = convert_version_to_proper_semantic(
        latest, package_name)
    libio_sem_version = convert_version_to_proper_semantic(libio, package_name)

    if latest_sem_version == zero_version and libio_sem_version == zero_version:
        return return_version
    try:
        return_version = libio
        if version_info_tuple(latest_sem_version) >= version_info_tuple(libio_sem_version):
            return_version = latest
    except ValueError:
        """In case of failure let's not show any latest version at all.
        Also, no generation of stack trace,
        as we are only intersted in the package that is causing the error."""
        current_app.logger.info(
            "Unexpected ValueError while selecting latest version for package {}. Debug:{}"
            .format(package_name,
                    {'latest': latest, 'libio': libio}))
        return_version = ''
    finally:
        return return_version


def fetch_file_from_github(url, filename, branch='master'):
    """Fetch file from github url."""
    base_url = 'https://raw.githubusercontent.com'
    try:
        if url.endswith('.git'):
            url = url[:-len('.git')]

        user, repo = url.split('/')[-2:]
        user = user.split(':')[-1]

        response = get('/'.join([base_url, user, repo, branch, filename]))
        if response.status_code != 200:
            raise ValueError
        return [{
            'filename': filename,
            'filepath': '/path',
            'content': response.content.decode('utf-8')
        }]
    except ValueError:
        current_app.logger.error('Error fetching file from given url')
    except Exception as e:
        current_app.logger.error('ERROR: {}'.format(str(e)))


def fetch_file_from_github_release(url, filename, token, ref=None):
    """Return file content from github release."""
    if token:
        try:
            github_obj = Github(token)
            if url.endswith('.git'):
                url = url[:-len('.git')]

            user, repo = url.split('/')[-2:]
            user = user.split(':')[-1]
            repository = github_obj.get_repo('/'.join([user, repo]))
            if ref:
                file_content = repository.get_file_contents(filename, ref).decoded_content
            else:
                file_content = repository.get_file_contents(filename).decoded_content
            return [{
                'filename': filename,
                'filepath': '/path',
                'content': file_content.decode('utf-8')
            }]
        except RateLimitExceededException:
            HTTPError(403, "Github API rate limit exceeded")
        except BadCredentialsException:
            HTTPError(401, "Invalid github access token")
        except GithubException as e:
            HTTPError(404, 'Github repository does not exist {}'.format(str(e)))
        except Exception as e:
            current_app.logger.error('An Exception occured while fetching file github release {}'
                                     .format(str(e)))
    else:
        current_app.logger.error("Github access token is not provided")


def is_valid(param):
    """Return true is the param is not a null value."""
    return param is not None


def generate_content_hash(content):
    """Return the sha1 digest of a string."""
    hash_object = hashlib.sha1(content.encode('utf-8'))
    return hash_object.hexdigest()


@lru_cache_function(max_size=2048, expiration=60 * 60 * 24)
def get_core_dependencies(runtime):
    """Return core dependencies for each runtime."""
    fetched_file = fetch_file_from_github_release(CORE_DEPENDENCIES_REPO_URL, 'core.json')
    dependencies = fetched_file[0].get('content', {})
    dep_runtime = dependencies.get(runtime, [])
    return dep_runtime
