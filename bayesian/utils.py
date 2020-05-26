"""Various utility functions."""

# TODO split this module into categories (graph DB, analyses etc.)

# Improve maintainability index
# TODO: https://github.com/fabric8-analytics/fabric8-analytics-server/issues/373

import datetime
import json
import os
import uuid
import shutil
import hashlib
import zipfile
import logging

from io import BytesIO
from functools import lru_cache
from selinon import run_flow
from lru import lru_cache_function
from flask import current_app
from flask.json import JSONEncoder
import semantic_version as sv
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from urllib.parse import urljoin
from f8a_worker.models import (Analysis, Ecosystem, Package, Version,
                               WorkerResult, StackAnalysisRequest, RecommendationFeedback)
from f8a_worker.utils import json_serial, MavenCoordinates, parse_gh_repo
from f8a_worker.process import Git
from f8a_worker.setup_celery import init_celery


from . import rdb
from .exceptions import HTTPError
from .default_config import BAYESIAN_COMPONENT_TAGGED_COUNT, CORE_DEPENDENCIES_REPO_URL, \
    STACK_ANALYSIS_REQUEST_TIMEOUT

from requests import get, post
from sqlalchemy.exc import SQLAlchemyError
from github import Github, BadCredentialsException, GithubException, RateLimitExceededException
from git import Repo, Actor

logger = logging.getLogger(__file__)

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

    # compute the elapsed time
    elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
    current_app.logger.debug("It took {t} seconds to start {f} flow.".format(
        t=elapsed_seconds, f=flow_name))
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
    # TODO: this is probably wrong - why not to check if analysis is None: at the beginning?
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
    # TODO: this is probably not Pythonic: why not to use:
    # for field in fields:
    #     if field not in analysis:
    #         return False
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


class GremlinComponentAnalysisResponse(object):
    """Wrapper around Gremlin component analysis response."""

    def __init__(self, package, version, response):
        """Initialize Gremlin Component Analyses."""
        self._package = package
        self._version = version
        self._cves = []
        # Gremlin query will always return two elements for response
        # response[0] = epv
        # response[1] = versions_with_no_cves
        self._nocve_versions = response[1].get('recommended_versions', [])
        self.results = []

        # response from Gremlin is kinda weird...
        for data in response[0]['epv']:
            this_version = data.get('version', {}).get('version', [None])[0]
            if this_version == self._version:
                self.results.append(data)
                if 'cve' in data:
                    self._cves.append(data.get('cve'))

    def has_cves(self):
        """Return True if this EPV has CVEs, False otherwise."""
        return bool(self._cves)

    def get_cve_maps(self):
        """Get all CVEs for this EPV."""
        cve_maps = []
        for cve in self._cves:
            cve_map = {
                'id': cve.get('cve_id')[0],
                'cvss': cve.get('cvss_v2')[0]
            }
            cve_maps.append(cve_map)

        return cve_maps

    def get_max_cvss_score(self):
        """Get highest CVSS score of all CVEs associated with this EPV."""
        max_cvss = 0.0
        for cve in self._cves:
            cvss = cve.get('cvss_v2')[0]
            try:
                cvss = float(cvss)
                if cvss > max_cvss:
                    max_cvss = cvss
            except (TypeError, ValueError):
                # It is possible that some CVEs don't have CVSS score - this is fine
                pass

        return max_cvss

    def get_version_without_cves(self):
        """Return higher version which doesn't have any CVEs. None if there is no such version."""
        input_version_tuple = version_info_tuple(
            convert_version_to_proper_semantic(self._version)
        )

        highest_version = ''

        for version in self._nocve_versions:
            graph_version_tuple = version_info_tuple(
                convert_version_to_proper_semantic(version)
            )
            if graph_version_tuple > input_version_tuple:
                if not highest_version:
                    highest_version = version
                highest_version_tuple = version_info_tuple(
                    convert_version_to_proper_semantic(highest_version)
                )
                # If version to recommend is closer to what a user is using then, use less than
                # If recommendation is to show highest version then, use greater than
                if graph_version_tuple > highest_version_tuple:
                    highest_version = version
        return highest_version


def generate_recommendation(data, package, input_version):
    """Generate recommendation for the package+version."""
    # Template Dict for recommendation
    reco = {
        'recommendation': {
            'component-analyses': {},
        }
    }

    if data:
        gremlin_resp = GremlinComponentAnalysisResponse(package, input_version, data)

        reco['data'] = gremlin_resp.results
        if gremlin_resp.has_cves():
            message = 'CVE/s found for Package - ' + package + ', Version - ' + \
                      input_version + '\n'
            cve_maps = gremlin_resp.get_cve_maps()
            message += ', '.join([x.get('id') for x in cve_maps])
            message += ' with a max cvss score of - ' + str(gremlin_resp.get_max_cvss_score())
            reco['recommendation']['component-analyses']['cve'] = cve_maps
        else:
            reco['recommendation'] = {}
            return {"result": reco}

        nocve_version = gremlin_resp.get_version_without_cves()
        if nocve_version:
            message += '\n It is recommended to use Version - ' + str(nocve_version)
            reco['recommendation']['change_to'] = str(nocve_version)

        reco['recommendation']['message'] = message

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
    """Read analysis for given package+version from the graph database.

    Fetching data from our GraphDB Node. Classical Flow
    """
    script1 = """\
g.V().has('pecosystem', ecosystem).has('pname', name).has('version', version).as('version')\
.in('has_version').dedup().as('package').select('version').coalesce(out('has_cve')\
.as('cve').select('package','version','cve').by(valueMap()),select('package','version')\
.by(valueMap()));\
"""

    payload = {
        'gremlin': script1,
        'bindings': {
            'ecosystem': ecosystem,
            'name': package,
            'version': version
        }
    }
    start = datetime.datetime.now()
    try:
        clubbed_data = []
        graph_req = post(gremlin_url, data=json.dumps(payload))

        if graph_req is not None:
            resp = graph_req.json()
            result_data = resp['result'].get('data')

            if not (result_data and len(result_data) > 0):
                # trigger unknown component flow in API for missing package
                return None

            clubbed_data.append({
                "epv": result_data
            })

            if "cve" in result_data[0]:
                if "latest_non_cve_version" in result_data[0]['package']:
                    clubbed_data.append({
                        "recommended_versions": result_data[0]['package']['latest_non_cve_version']
                    })
                else:
                    script2 = "g.V().has('pecosystem', ecosystem).has('pname', name)" \
                              ".has('version', version).in('has_version')" \
                              ".out('has_version').not(out('has_cve')).values('version').dedup();"
                    payload = {
                        'gremlin': script2,
                        'bindings': {
                            'ecosystem': ecosystem,
                            'name': package,
                            'version': version
                        }
                    }

                    graph_req2 = post(gremlin_url, data=json.dumps(payload))
                    if graph_req2 is not None:
                        resp2 = graph_req2.json()
                        clubbed_data.append({
                            "recommended_versions": resp2['result']['data']
                        })
            else:
                clubbed_data.append({
                    "recommended_versions": []
                })
    except Exception as e:
        logger.debug(' '.join([type(e), ':', str(e)]))
        return None
    finally:
        elapsed_seconds = (datetime.datetime.now() - start).total_seconds()
        epv = "{e}/{p}/{v}".format(e=ecosystem, p=package, v=version)
        logger.debug("Gremlin request {p} took {t} seconds.".format(p=epv,
                                                                    t=elapsed_seconds))

    resp = generate_recommendation(clubbed_data, package, version)
    return resp


class CveByDateEcosystemUtils:
    """Contains Gremlin queries and functions to serve CVEs.

    CVEs bydate & further filter by ecosystem if provided.
    """

    # Get CVEs information by date
    cve_epv_nodes_template = """\
    g.V().has('cve_id', cve_id)\
    .in("has_cve").valueMap()\
    """

    cve_nodes_by_date_ecosystem_script_template_all = """\
    g.V().has('modified_date', modified_date)\
    .has('cecosystem',ecosystem)\
    .valueMap()\
    """

    def __init__(self, cve_id, bydate=None,
                 ecosystem='all', date_range=7):
        """Initialize CvaeDate Ecosystem Utils."""
        self._cve_id = cve_id
        if cve_id is None:
            self._bydate = bydate
            self._ecosystem = ecosystem
            self._date_range = date_range

    def get_cves_by_date_ecosystem(self):
        """Call graph and get CVEs by date and ecosystem."""
        program_startdate = datetime.datetime.strptime(self._bydate, "%Y%m%d")
        didx = [program_startdate - datetime.timedelta(days=x) for x in range(0, self._date_range)]
        gremlin_json = []

        try:
            for dt in didx:
                dt = datetime.datetime.strftime(dt, '%Y%m%d')
                # Gremlin script execution
                script = self.cve_nodes_by_date_ecosystem_script_template_all

                self._ecosystem = self._ecosystem.lower()
                bindings = {
                    'modified_date': dt, 'ecosystem': self._ecosystem
                }
                """Call Gremlin and get the CVE information."""
                json_payload = self.prepare_payload(script, bindings)

                response = post(gremlin_url, json=json_payload)
                gremlin_json.extend(response.json().get('result', {}).get('data', []))
        except Exception:
            raise

        cve_list = self.prepare_response_cve(gremlin_json)
        return cve_list

    def get_cves_epv_by_date(self):
        """Call graph and get CVEs by date and ecosystem."""
        script = self.cve_epv_nodes_template
        bindings = {'cve_id': self._cve_id}
        """Call Gremlin and get the CVE EPV information."""
        json_payload = self.prepare_payload(script, bindings)
        try:
            response = post(gremlin_url, json=json_payload)
        except Exception:
            raise
        epv_list = self.prepare_response_epv(response.json())
        return epv_list

    def prepare_payload(self, script, bindings):
        """Prepare payload."""
        payload = {'gremlin': script, 'bindings': bindings}

        return payload

    def prepare_response_cve(self, gremlin_json):
        """Prepare response to be sent to user based on Gremlin data."""
        cve_list_add = []
        # resp = gremlin_json.get('result', {}).get('data', [])
        for cve in gremlin_json:
            cve_dict = {
                "cve_id": cve.get('cve_id', [None])[0],
                "cvss_v2": cve.get('cvss_v2', [None])[0],
                "description": cve.get('description', [None])[0],
                "ecosystem": cve.get('cecosystem', [None])[0],
                "fixed_in": cve.get('fixed_in', [None])[0],
                "link": "https://nvd.nist.gov/vuln/detail/" +
                        cve.get('cve_id', [''])[0]
            }
            cve_list_add.append(cve_dict)

        response = {
            "count": len(cve_list_add),
            "add": cve_list_add
        }

        return response

    def prepare_response_epv(self, gremlin_json):
        """Prepare response to be sent to user based on Gremlin data."""
        epv_list_add = []
        resp = gremlin_json.get('result', {}).get('data', [])
        for epv in resp:
            epv_dict = {
                "name": epv.get('pname', [None])[0],
                "version": epv.get('version', [None])[0]
            }
            epv_list_add.append(epv_dict)

        response = {
            "count": len(epv_list_add),
            "add": epv_list_add
        }

        return response


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

    # compute elapsed time
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

    # compute elapsed time
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
        except Exception:
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
        # TODO: test variable is not needed in the following code
        # TODO: just return True from the loop
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


@lru_cache(maxsize=128)
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
    """Return the latest version among current latest version and libio version."""
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
        # TODO: refactor user+repository retrieving into separate function
        # TODO: the same code as in fetch_file_from_github_release
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
            # TODO: refactor user+repository retrieving into separate function
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
    fetched_file = fetch_file_from_github(CORE_DEPENDENCIES_REPO_URL, 'core.json')
    dependencies = json.loads(fetched_file[0].get('content', "{}"))
    dep_runtime = dependencies.get(runtime, [])
    return dep_runtime


def create_directory_structure(root=os.getcwd(), struct=dict()):
    """Create a directory structure.

    root: String path to root directory
    struct: Dict object describing dir structure
        an example:

            {
                'name': 'parentdir',
                'type': 'dir',
                'contains': [
                    {
                        'name': 'hello.txt',
                        'type': 'file',
                        'contains': "Some text"
                    },
                    {
                        'name': 'childdir',
                        'type': 'dir',
                    }
                ]
            }
    """
    _root = os.path.abspath(root)
    if isinstance(struct, list):
        for item in struct:
            create_directory_structure(_root, item)
    else:
        # default type is file if not defined
        _type = struct.get('type', 'file')
        _name = struct.get('name')
        _contains = struct.get('contains', '')
        if _name:
            _root = os.path.join(_root, _name)
            if _type == 'file':
                with open(_root, 'wb') as _file:
                    if not isinstance(_contains, (bytes, bytearray)):
                        _contains = _contains.encode()
                    _file.write(_contains)
            else:
                os.makedirs(_root, exist_ok=True)
                if isinstance(_contains, (list, dict)):
                    create_directory_structure(_root, _contains)


def push_repo(token, local_repo, remote_repo, author_name=None, author_email=None,
              user=None, organization=None, auto_remove=False):
    """Initialize a git repo and push the code to the target repo."""
    commit_msg = 'Initial commit'
    if not os.path.exists(local_repo):
        raise ValueError("Directory {} does not exist.".format(local_repo))
    repo = Repo.init(local_repo)
    repo.git.add(all=True)
    # TODO: "openshiftio-launchpad" -> config module
    # TODO: "obsidian-leadership@redhat.com" -> config module
    committer = Actor(author_name or os.getenv("GIT_COMMIT_AUTHOR_NAME", "openshiftio-launchpad"),
                      author_email or os.getenv("GIT_COMMIT_AUTHOR_EMAIL",
                                                "obsidian-leadership@redhat.com"))

    # TODO: refactor this code into new function
    if organization is None:
        # try to fetch user instead of organization
        try:
            organization = Github(token).get_user().login
        except RateLimitExceededException:
            raise HTTPError(403, "Github API rate limit exceeded")
        except BadCredentialsException:
            raise HTTPError(401, "Invalid github access token")
        except Exception as exc:
            raise HTTPError(500, "Unable to get the username {}".format(str(exc)))

    repo.index.commit(commit_msg, committer=committer, author=committer)
    remote_uri = 'https://{user}:{token}@github.com/{user}/{remote_repo}'\
        .format(user=organization, token=token, remote_repo=remote_repo)
    try:
        origin = repo.create_remote('origin', remote_uri)
        origin.push('master')
    except Exception as exc:
        raise HTTPError(500, "Unable to Push the code: {}".format(str(exc.stderr)))
    finally:
        if auto_remove and os.path.exists(local_repo):
            shutil.rmtree(local_repo)


@lru_cache_function(max_size=2048, expiration=2 * 60 * 60 * 24)
def get_booster_core_repo(ref='master'):
    """Return core booster dependencies repo path."""
    _base_url = 'https://github.com/{user}/{repo}/archive/{ref}.zip'
    _url = CORE_DEPENDENCIES_REPO_URL
    # TODO: refactor user+repository retrieving into separate function
    # TODO: test the refactored code
    # TODO: the same code as in fetch_file_from_github_release
    if _url.endswith('.git'):
        _url = _url[:-len('.git')]
    user, repo = _url.split('/')[-2:]
    user = user.split(':')[-1]

    url = _base_url.format(user=user, repo=repo, ref=ref)
    resp = get(url, stream=True)
    repo_path = os.path.abspath(os.path.join('/tmp', '-'.join([repo, ref])))
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)
    if resp.status_code != 200:
        raise HTTPError(500, "Unable to access url {} \n STATUS_CODE={}".format(
            url, resp.status_code))
    _zip = zipfile.ZipFile(BytesIO(resp.content))
    _zip = _zip.extractall('/tmp')
    return repo_path


def get_recommendation_feedback_by_ecosystem(ecosystem):
    """Return json object representing recommendation feedback."""
    # TODO: it needs to be refactored into two functions:
    # 1) read data from RDS
    # 2) reshape results (from feedback_list into result)
    try:
        feedback_list = rdb.session.query(RecommendationFeedback). \
            join(StackAnalysisRequest).join(Ecosystem). \
            filter(Ecosystem.name == ecosystem). \
            filter(RecommendationFeedback.stack_id == StackAnalysisRequest.id).all()
        result = []
        for feedback in feedback_list:
            if not feedback.stack_request.dep_snapshot:
                dependencies = []
            else:
                dependencies = feedback.stack_request.dep_snapshot.\
                    get('result', [{}])[0].\
                    get('details', [{}])[0].\
                    get('_resolved', [])

            feedback_dict = {
                "recommendation_type": feedback.recommendation_type,
                "recommended_package_name": feedback.package_name,
                "feedback": feedback.feedback_type,
                "input_package_list": dependencies
            }
            result.append(feedback_dict)

        return result
    except SQLAlchemyError:
        rdb.session.rollback()
        raise


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
    "pypi"
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
