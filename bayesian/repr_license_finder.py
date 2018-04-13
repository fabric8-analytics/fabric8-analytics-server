"""Identifies representative license for go eco repo by considering all the dependencies."""
from __future__ import division
from flask import current_app
from requests import get, post, exceptions
import json
from f8a_worker.graphutils import GREMLIN_SERVER_URL_REST
from f8a_worker.graphutils import LICENSE_SCORING_URL_REST
from f8a_worker.base import BaseTask
from f8a_worker.utils import get_session_retry
from .dependency_finder import DependencyFinder
from . import rdb, cache
from .utils import fetch_file_from_github
import requests
import logging
import traceback


# Returns glide.lock file content as  a string for the github url given

class GetReprLicense(object):
    """Returns representative license for given github url and ecosystem."""

    def __init__(self, url, ecosystem, req_id, license_api):
        """Summary.

        input:url:repo url to find repr_license
        ecosystem:ecosystem of the repo
        output:repr_license. Calculates the representative license at
        the stack level by considering the license info of all the dependencies
        and transitive dependencies.Currently supports only go ecosystem.
        """
        self.external_request_id = req_id
        self.url = url
        self.ecosystem = ecosystem
        self.license_api = license_api

    def godep_extractor(self, **arguments):
        """Fetch go dependencies by parsing mercator output."""
        result = {}
        ecosystem = arguments['result'][0]['details'][0]['ecosystem']
        dependency_info = arguments['result'][0]['details'][0]['_resolved']
        for pkg_info in dependency_info:
            result[str(pkg_info.get('package'))] = str(pkg_info.get('version'))
        return result

    def fetch_license_from_graph(self, **a):
        """Fetch license from graph for all go deps."""
        license_dict_list = []
        license_dict_modify = []
        dep_pkg_list_known = []
        dep_pkg_list_unknown = []

        for name, version in a.items():
            result = []
            qstring = ("g.V().has('pecosystem','" + self.ecosystem + "').has('pname','" +
                       name + "').has('version','" + version + "')")
            payload = {'gremlin': qstring}
            graph_req = get_session_retry().post(GREMLIN_SERVER_URL_REST, data=json.dumps(payload))
            if graph_req.status_code == 200:
                graph_resp = graph_req.json()
                if graph_resp.get('result', {}).get('data'):
                    result.append(graph_resp["result"])
                    if result[0]['data'][0]['properties']['version'][0]['value'] == version:
                        license_val = result[0]['data'][0]['properties']['licenses'][0]['value']
                        license_id = result[0]['data'][0]['properties']['licenses'][0]['id']
                        dep_pkg_list_known.append(
                            self.ecosystem + ":" + name + ":" + version + ":" +
                            license_val + ":" + license_id)
                        license_dict_list.append(
                            {'pname': name, 'version': version, 'license_name':
                                license_val, 'license_id': license_id})
                        license_dict_modify.append({"package": name, "version": version,
                                                    "licenses": [license_val]})
                else:
                    license_dict_modify.append({"package": name,
                                                "version": version, "licenses": []})
                    dep_pkg_list_unknown.append(self.ecosystem + ":" + name + ":" + version)
                    continue

        return {"packages": license_dict_modify}

    def caller(self):
        """Execute method for this module."""
        arguments = {'ecosystem': self.ecosystem, 'url': self.url,
                     'external_request_id': self.external_request_id}
        a = DependencyFinder()
        db = rdb.session()
        try:
            b = fetch_file_from_github(self.url, 'glide.lock')
            b[0]['ecosystem'] = arguments['ecosystem']
            executor = a.execute(arguments, db, b)
            go_deps = self.godep_extractor(**executor)
            graph_output = self.fetch_license_from_graph(**go_deps)
            r = requests.post(self.license_api, json=graph_output)
            json_out = r.json()
            if json_out['stack_license'] is None:
                json_out['stack_license'] = 'Unknown'
            return json_out
        except Exception:
            msg = traceback.format_exc()
            logging.error("Unexpected error happened!\n{}".format(msg))
