from __future__ import division
import json
import traceback
import datetime
import logging

import requests
import os
from collections import Counter, defaultdict
import re
import semantic_version as sv

from f8a_worker.graphutils import (GREMLIN_SERVER_URL_REST, create_package_dict,
                                   select_latest_version, LICENSE_SCORING_URL_REST)
from f8a_worker.utils import get_session_retry
from .stack_aggregator import extract_user_stack_package_licenses

_logger = logging.getLogger(__name__)

#TO BE REMOVED
GREMLIN_SERVER_URL_REST = 'http://bayesian-gremlin-http-preview-b6ff-bayesian-preview.b6ff.rh-idev.openshiftapps.com:80'
LICENSE_SCORING_URL_REST = 'http://bayesian-license-scoring-bayesian-preview.b6ff.rh-idev.openshiftapps.com:80'
#TO BE REMOVED

danger_word_list = ["drop\(\)", "V\(\)", "count\(\)"]
remove = '|'.join(danger_word_list)
pattern = re.compile(r'(' + remove + ')', re.IGNORECASE)
pattern_to_save = '[^\w\*\.Xx\-\>\=\<\~\^\|\/\:]'
pattern_n2_remove = re.compile(pattern_to_save)

class GraphDB:

    def __init__(self):
        self._bayesian_graph_url = GREMLIN_SERVER_URL_REST

    def execute_gremlin_dsl(self, payload):
        """Execute the gremlin query and return the response."""
        try:
            response = get_session_retry().post(self._bayesian_graph_url, data=json.dumps(payload))
            if response.status_code != 200:
                _logger.error("HTTP error {}. Error retrieving Gremlin data.".format(
                    response.status_code))
                return None
            else:
                json_response = response.json()
                return json_response
        except Exception:
            _logger.error("Failed retrieving Gremlin data.")
            return None

    def get_response_data(self, json_response, data_default):
        """Data default parameters takes what should data to be returned."""
        return json_response.get("result", {}).get("data", data_default)

    def get_version_information(self, input_list, ecosystem):
        """Fetch the version information for each of the packages
        Also remove EPVs with CVEs and ones not present in Graph
        """
        input_packages = [package for package in input_list]
        str_query = "g.V().has('ecosystem',ecosystem).has('name',within(input_packages))" \
                    ".as('pkg').out('has_version')" \
                    ".hasNot('cve_ids').as('ver').select('pkg','ver').by(valueMap()).dedup()"
        payload = {
            'gremlin': str_query,
            'bindings': {
                'ecosystem': ecosystem,
                'input_packages': input_packages
            }
        }

        # Query Gremlin with packages list to get their version information
        gremlin_response = self.execute_gremlin_dsl(payload)
        if gremlin_response is None:
            return []
        response = self.get_response_data(gremlin_response, [{0: 0}])
        return response

    def filter_versions(self, epv_list, input_stack):
        """First filter fetches only EPVs that
        1. has No CVEs
        2. are Present in Graph
        Apply additional filter based on following. That is sorted based on
        3. Latest Version
        4. Dependents Count in Github Manifest Data
        5. Github Release Date"""

        pkg_dict = defaultdict(dict)
        new_dict = defaultdict(dict)
        filtered_comp_list = []
        for epv in epv_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            version = epv.get('ver', {}).get('version', [''])[0]
            # needed for maven version like 1.5.2.RELEASE to be converted to
            # 1.5.2-RELEASE for semantic version to work'
            semversion = version.replace('.', '-', 3)
            semversion = semversion.replace('-', '.', 2)
            if name and version:
                # Select Latest Version and add to filter_list if
                # latest version is > current version
                latest_version = select_latest_version(
                    epv.get('pkg').get('libio_latest_version', [''])[0],
                    epv.get('pkg').get('latest_version', [''])[0])
                if latest_version and latest_version == version:
                    try:
                        if sv.SpecItem('>=' + input_stack.get(name, '0.0.0')).match(
                           sv.Version(semversion)):
                            pkg_dict[name]['latest_version'] = latest_version
                            new_dict[name]['latest_version'] = epv.get('ver')
                            new_dict[name]['pkg'] = epv.get('pkg')
                            filtered_comp_list.append(name)
                    except ValueError:
                        pass

                # Check for Dependency Count Attribute. Add Max deps count version
                # if version > current version
                deps_count = epv.get('ver').get('dependents_count', [-1])[0]
                if deps_count > 0:
                    if 'deps_count' not in pkg_dict[name] or \
                       deps_count > pkg_dict[name].get('deps_count', {}).get('deps_count', 0):
                        try:
                            if sv.SpecItem('>=' + input_stack.get(name, '0.0.0')).match(
                               sv.Version(semversion)):
                                pkg_dict[name]['deps_count'] = {"version": version,
                                                                "deps_count": deps_count}
                                new_dict[name]['deps_count'] = epv.get('ver')
                                new_dict[name]['pkg'] = epv.get('pkg')

                                filtered_comp_list.append(name)
                        except ValueError:
                            pass

                # Check for github release date. Add version with most recent github release date
                gh_release_date = epv.get('ver').get('gh_release_date', [0])[0]
                if gh_release_date > 0.0:
                    if 'gh_release_date' not in pkg_dict[name] or \
                       gh_release_date > \
                       pkg_dict[name].get('gh_release_date', {}).get('gh_release_date', 0):
                        try:
                            if sv.SpecItem('>=' + input_stack.get(name, '0.0.0')).match(
                               sv.Version(semversion)):
                                pkg_dict[name]['gh_release_date'] = {
                                    "version": version,
                                    "gh_release_date": gh_release_date}
                                new_dict[name]['gh_release_date'] = epv.get('ver')
                                new_dict[name]['pkg'] = epv.get('pkg')
                                filtered_comp_list.append(name)
                        except ValueError:
                            pass

        new_list = []
        for package, contents in new_dict.items():
            if 'latest_version' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['latest_version']})
            elif 'deps_count' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['deps_count']})
            elif 'gh_release_date' in contents:
                new_list.append({"pkg": contents['pkg'], "ver": contents['gh_release_date']})

        return new_list, filtered_comp_list

    def get_topics_for_alt(self, comp_list, pgm_dict):
        """Gets topics from pgm and associate with filtered versions from Graph"""
        for epv in comp_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            if name:
                for pgm_pkg_key, pgm_list in pgm_dict.items():
                    for pgm_epv in pgm_list:
                        if name == pgm_epv.get('package_name', ''):
                            epv['pkg']['pgm_topics'] = pgm_epv.get('topic_list', [])

        return comp_list

    def get_topics_for_comp(self, comp_list, pgm_list):
        """Gets topics from pgm and associate with filtered versions from Graph"""
        for epv in comp_list:
            name = epv.get('pkg', {}).get('name', [''])[0]
            if name:
                for pgm_epv in pgm_list:
                    if name == pgm_epv.get('package_name', ''):
                        epv['pkg']['pgm_topics'] = pgm_epv.get('topic_list', [])
                        epv['pkg']['cooccurrence_probability'] = pgm_epv.get(
                            'cooccurrence_probability', 0)
                        epv['pkg']['cooccurrence_count'] = pgm_epv.get(
                            'cooccurrence_count', 0)

        return comp_list

def invoke_license_analysis_service(user_stack_packages, alternate_packages, companion_packages):
    license_url = LICENSE_SCORING_URL_REST + "/api/v1/stack_license"

    payload = {
        "packages": user_stack_packages,
        "alternate_packages": alternate_packages,
        "companion_packages": companion_packages
    }

    json_response = {}
    try:
        lic_response = get_session_retry().post(license_url, data=json.dumps(payload))
        lic_response.raise_for_status()  # raise exception for bad http-status codes
        json_response = lic_response.json()
    except requests.exceptions.RequestException:
        _logger.exception("Unexpected error happened while invoking license analysis!")
        pass

    return json_response


def apply_license_filter(user_stack_components, epv_list_alt, epv_list_com):
    license_score_list_alt = []
    for epv in epv_list_alt:
        license_scoring_input = {
            'package': epv.get('pkg', {}).get('name', [''])[0],
            'version': epv.get('ver', {}).get('version', [''])[0],
            'licenses': epv.get('ver', {}).get('declared_licenses', [])
        }
        license_score_list_alt.append(license_scoring_input)

    license_score_list_com = []
    for epv in epv_list_com:
        license_scoring_input = {
            'package': epv.get('pkg', {}).get('name', [''])[0],
            'version': epv.get('ver', {}).get('version', [''])[0],
            'licenses': epv.get('ver', {}).get('declared_licenses', [])
        }
        license_score_list_com.append(license_scoring_input)

    # Call license scoring to find license filters
    la_output = invoke_license_analysis_service(user_stack_components,
                                                license_score_list_alt,
                                                license_score_list_com)

    conflict_packages_alt = conflict_packages_com = []
    if la_output.get('status') == 'Successful' and la_output.get('license_filter') is not None:
        license_filter = la_output.get('license_filter', {})
        conflict_packages_alt = license_filter.get('alternate_packages', {})\
                                              .get('conflict_packages', [])
        conflict_packages_com = license_filter.get('companion_packages', {})\
                                              .get('conflict_packages', [])

    list_pkg_names_alt = []
    for epv in epv_list_alt[:]:
        name = epv.get('pkg', {}).get('name', [''])[0]
        if name in conflict_packages_alt:
            list_pkg_names_alt.append(name)
            epv_list_alt.remove(epv)

    list_pkg_names_com = []
    for epv in epv_list_com[:]:
        name = epv.get('pkg', {}).get('name', [''])[0]
        if name in conflict_packages_com:
            list_pkg_names_com.append(name)
            epv_list_com.remove(epv)

    output = {
        'filtered_alt_packages_graph': epv_list_alt,
        'filtered_list_pkg_names_alt': list_pkg_names_alt,
        'filtered_comp_packages_graph': epv_list_com,
        'filtered_list_pkg_names_com': list_pkg_names_com
    }
    _logger.info("License Filter output: {}".format(json.dumps(output)))

    return output


class RecommendationTask():
    _analysis_name = 'recommendation_v2'
    description = 'Get Recommendation'

    def call_pgm(self, payload):
        print (payload)

        """Calls the PGM model with the normalized manifest information to get
        the relevant packages"""
        try:
            # TODO remove hardcodedness for payloads with multiple ecosystems
            if payload and 'ecosystem' in payload[0]:
                print ('#### %r' % payload[0])

                #PGM_SERVICE_HOST = os.environ.get(
                #    "PGM_SERVICE_HOST") + "-" + payload[0]['ecosystem']
                #PGM_URL_REST = "http://{host}:{port}".format(
                #    host=PGM_SERVICE_HOST,
                #    port=os.environ.get("PGM_SERVICE_PORT"))
                
                ## TO BE REMOVED
                PGM_URL_REST = 'http://bayesian-kronos-maven-schoudhu-greenfield-test.dev.rdu2c.fabric8.io:80'
                ## TO BE REMOVED
                pgm_url = PGM_URL_REST + "/api/v1/schemas/kronos_scoring"
                print ('PGM URL: %s' % pgm_url)
                response = get_session_retry().post(pgm_url, json=payload)
                if response.status_code != 200:
                    print("HTTP error {}. Error retrieving PGM data.".format(
                        response.status_code))
                    return None
                else:
                    json_response = response.json()
                    return json_response
            else:
                print('Payload information is not passed in the call, '
                               'Quitting! PGM\'s call')
        except Exception:
            print("Failed retrieving PGM data.")
            return None

    def execute(self, arguments=None):
        results = arguments['result']
        external_request_id = arguments['external_request_id']

        input_task_for_pgm = []
        recommendations = []
        input_stack = {}
        for result in results:
            temp_input_stack = {d["package"]: d["version"] for d in
                                result.get("details", [])[0].get("_resolved")}
            input_stack.update(temp_input_stack)

        for result in results:
            details = result['details'][0]
            resolved = details['_resolved']
            manifest_file_path = details['manifest_file_path']

            recommendation = {
                'companion': [],
                'alternate': [],
                'usage_outliers': [],
                'manifest_file_path': manifest_file_path
            }
            new_arr = [r['package'] for r in resolved]
            json_object = {
                'ecosystem': details['ecosystem'],
                'comp_package_count_threshold': int(os.environ.get('MAX_COMPANION_PACKAGES', 5)),
                'alt_package_count_threshold': int(os.environ.get('MAX_ALTERNATE_PACKAGES', 2)),
                'outlier_probability_threshold': float(os.environ.get('OUTLIER_THRESHOLD', 0.6)),
                'unknown_packages_ratio_threshold':
                    float(os.environ.get('UNKNOWN_PACKAGES_THRESHOLD', 0.3)),
                'user_persona': "1",  # TODO - remove janus hardcoded value
                                      # completely and assing a cateogory here
                'package_list': new_arr
            }
            input_task_for_pgm.append(json_object)

            # Call PGM and get the response
            start = datetime.datetime.utcnow()
            pgm_response = self.call_pgm(input_task_for_pgm)
            elapsed_seconds = (datetime.datetime.utcnow() - start).total_seconds()
            msg = 'It took {t} seconds to get response from PGM ' \
                  'for external request {e}.'.format(t=elapsed_seconds,
                                                     e=external_request_id)
            print(msg)

            # From PGM response process companion and alternate packages and
            # then get Data from Graph
            # TODO - implement multiple manifest file support for below loop

            if pgm_response is not None:
                for pgm_result in pgm_response:
                    companion_packages = []
                    ecosystem = pgm_result['ecosystem']

                    # Get usage based outliers
                    recommendation['usage_outliers'] = \
                        pgm_result['outlier_package_list']

                    # Append Topics for User Stack
                    recommendation['input_stack_topics'] = pgm_result.get('package_to_topic_dict',
                                                                          {})

                    for pkg in pgm_result['companion_packages']:
                        companion_packages.append(pkg['package_name'])

                    # Get Companion Packages from Graph
                    comp_packages_graph = GraphDB().get_version_information(companion_packages,
                                                                            ecosystem)

                    # Apply Version Filters
                    filtered_comp_packages_graph, filtered_list = GraphDB().filter_versions(
                        comp_packages_graph, input_stack)

                    filtered_companion_packages = \
                        set(companion_packages).difference(set(filtered_list))
                    _logger.info("Companion Packages Filtered for external_request_id {} {}"
                                 .format(external_request_id,
                                         filtered_companion_packages))

                    # Get the topmost alternate package for each input package

                    # Create intermediate dict to Only Get Top 1 companion
                    # packages for the time being.
                    temp_dict = {}
                    for pkg_name, contents in pgm_result['alternate_packages'].items():
                        pkg = {}
                        for ind in contents:
                            pkg[ind['package_name']] = ind['similarity_score']
                        temp_dict[pkg_name] = pkg

                    final_dict = {}
                    alternate_packages = []
                    for pkg_name, contents in temp_dict.items():
                        # For each input package
                        # Get only the topmost alternate package from a set of
                        # packages based on similarity score
                        top_dict = dict(Counter(contents).most_common(1))
                        for alt_pkg, sim_score in top_dict.items():
                            final_dict[alt_pkg] = {
                                'version': input_stack[pkg_name],
                                'replaces': pkg_name,
                                'similarity_score': sim_score
                            }
                            alternate_packages.append(alt_pkg)

                    # Get Alternate Packages from Graph
                    alt_packages_graph = GraphDB().get_version_information(
                        alternate_packages, ecosystem)

                    # Apply Version Filters
                    filtered_alt_packages_graph, filtered_list = GraphDB().filter_versions(
                        alt_packages_graph, input_stack)

                    filtered_alternate_packages = \
                        set(alternate_packages).difference(set(filtered_list))
                    _logger.info("Alternate Packages Filtered for external_request_id {} {}"
                                 .format(external_request_id,
                                         filtered_alternate_packages))

                    # apply license based filters
                    list_user_stack_comp = extract_user_stack_package_licenses(resolved, ecosystem)
                    license_filter_output = apply_license_filter(list_user_stack_comp,
                                                                 filtered_alt_packages_graph,
                                                                 filtered_comp_packages_graph)

                    lic_filtered_alt_graph = license_filter_output['filtered_alt_packages_graph']
                    lic_filtered_comp_graph = license_filter_output['filtered_comp_packages_graph']
                    lic_filtered_list_alt = license_filter_output['filtered_list_pkg_names_alt']
                    lic_filtered_list_com = license_filter_output['filtered_list_pkg_names_com']

                    if len(lic_filtered_list_alt) > 0:
                        s = set(filtered_alternate_packages).difference(set(lic_filtered_list_alt))
                        msg = \
                            "Alternate Packages filtered (licenses) for external_request_id {} {}"\
                            .format(external_request_id, s)
                        _logger.info(msg)

                    if len(lic_filtered_list_com) > 0:
                        s = set(filtered_companion_packages).difference(set(lic_filtered_list_com))
                        msg = \
                            "Companion Packages filtered (licenses) for external_request_id {} {}"\
                            .format(external_request_id, s)
                        _logger.info(msg)

                    # Get Topics Added to Filtered Packages
                    topics_comp_packages_graph = GraphDB().\
                        get_topics_for_comp(lic_filtered_comp_graph,
                                            pgm_result['companion_packages'])

                    # Create Companion Block
                    comp_packages = create_package_dict(topics_comp_packages_graph)
                    recommendation['companion'] = comp_packages

                    # Get Topics Added to Filtered Packages
                    topics_comp_packages_graph = GraphDB().\
                        get_topics_for_alt(lic_filtered_alt_graph,
                                           pgm_result['alternate_packages'])

                    # Create Alternate Dict
                    alt_packages = create_package_dict(topics_comp_packages_graph, final_dict)
                    recommendation['alternate'] = alt_packages

            recommendations.append(recommendation)
        return {'recommendations': recommendations}
