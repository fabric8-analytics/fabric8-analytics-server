"""Identifies representative license for go eco repo by considering all the dependencies."""

from __future__ import division
from flask import current_app
from requests import get, post, exceptions
import json
from .utils import GREMLIN_SERVER_URL_REST
from f8a_worker.utils import get_session_retry
from .utils import fetch_file_from_github
import requests
import logging
import traceback


class GetReprLicense:
    """Returns representative license for given github url and ecosystem."""

    def __init__(self, url, ecosystem, license_api):
        """Summary.

        input:url:repo url to find repr_license
        ecosystem:ecosystem of the repo
        output:repr_license. Calculates the representative license at
        the stack level by considering the license info of all the dependencies
        and transitive dependencies.Currently supports only go ecosystem
        """
        self.url = url
        self.ecosystem = ecosystem
        self.license_api = license_api

    def godep_extractor(self, response_glide_pkg):
        """Fetch go dependencies by parsing glide.lock file."""
        result = {}
        pkg_result = response_glide_pkg[0]['content']
        pkg_list = pkg_result.splitlines()
        for index, element in enumerate(pkg_list):
            if element.startswith('- name'):
                pkg_name = element.split(':')[1].strip()
                pkg_version = pkg_list[index + 1].split('version:')[1].strip()
                result[pkg_name] = pkg_version
        return result

    def fetch_license_from_graph(self, **a):
        """Fetch license from grph for all go deps."""
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
                            {'pname': name, 'version': version, 'license_name': license_val,
                             'license_id': license_id})
                        license_dict_modify.append({"package": name, "version": version,
                                                    "licenses": [license_val]})
                else:
                    license_dict_modify.append({"package": name, "version": version,
                                                "licenses": []})
                    dep_pkg_list_unknown.append(self.ecosystem + ":" + name + ":" + version)
                    continue

        return {"packages": license_dict_modify}

    def caller(self):
        """Execute method for all the above functions."""
        try:
            glide_data = fetch_file_from_github(self.url, 'glide.lock')
            extracted_info = self.godep_extractor(glide_data)
            license_json = self.fetch_license_from_graph(**extracted_info)
            r = requests.post(self.license_api, json=license_json)
            json_out = r.json()
            if json_out['stack_license'] is None:
                json_out['stack_license'] = 'Unknown'
            return json_out
        except Exception:
            msg = traceback.format_exc()
            logging.error("Unexpected error happened!\n{}".format(msg))
