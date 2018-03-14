#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from flask import current_app
from requests import get, post, exceptions
from __future__ import division
import json
from f8a_worker.graphutils import GREMLIN_SERVER_URL_REST
from f8a_worker.graphutils import LICENSE_SCORING_URL_REST
from f8a_worker.base import BaseTask
from f8a_worker.utils import get_session_retry
import requests
import logging
import traceback


# Retunrs glide.lock file content as  a string for the github url given

class get_repr_license(object):

    def __init__(self, url, ecosystem, license_api):
        self.url = url
        self.ecosystem = ecosystem
        self.license_api = license_api

    def fetch_go_deps_from_github(self):
        """Fetch glide.lock from github url."""
        base_url = 'https://raw.githubusercontent.com'
        branch = 'master'
        filename = 'glide.lock'

        try:
            if self.url.endswith('.git'):
                self.url = self.url[:-len('.git')]

            user, repo = self.url.split('/')[-2:]
            user = user.split(':')[-1]

            response = get('/'.join([base_url, user, repo, branch, filename]))
            if response.status_code != 200:
                raise ValueError
            return [{
                'filename': 'glide.lock',
                'filepath': '/path',
                'content': response.content.decode('utf-8')
            }]
        except ValueError:
            print('Error fetching file from given url')
        except Exception as e:
            print('ERROR: {}'.format(str(e)))

    def godep_extractor(self, response_glide_pkg):

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
                            self.ecosystem + ":" + name + ":" + version + ":" + license_val + ":" + license_id)
                        license_dict_list.append(
                            {'pname': name, 'version': version, 'license_name': license_val, 'license_id': license_id})
                        license_dict_modify.append({"package": name, "version": version, "licenses": [license_val]})
                else:
                    license_dict_modify.append({"package": name, "version": version, "licenses": []})
                    dep_pkg_list_unknown.append(self.ecosystem + ":" + name + ":" + version)
                    continue

        return {"packages": license_dict_modify}

    def caller(self):
        try:
            r = requests.post(self.license_api, json=self.fetch_license_from_graph(
                **(self.godep_extractor(self.fetch_go_deps_from_github()))))
            json_out = r.json()
            if json_out['stack_license'] is None:
                json_out['stack_license'] = 'Unknown'
            return json_out
        except Exception:
            msg = traceback.format_exc()
            logging.error("Unexpected error happened!\n{}".format(msg))

