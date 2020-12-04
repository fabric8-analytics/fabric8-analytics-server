# Copyright © 2020 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Dharmendra G Patel <dhpatel@redhat.com>
#
"""Test stack analyses class."""

import pytest
import unittest
from pathlib import Path
from unittest.mock import patch
from pydantic.error_wrappers import ValidationError
from bayesian.utility.v2.stack_analyses import StackAnalyses, SAInvalidInputException
from bayesian.utility.v2.sa_models import StackAnalysesPostRequest
from bayesian.utility.v2.backbone_server import BackboneServerException
from bayesian.utility.db_gateway import RDBSaveException
from werkzeug.datastructures import FileStorage


class TestStackAnalyses(unittest.TestCase):
    """Stack Analyses Unit Tests."""

    def test_sa_invalid_manifest_file(self):
        """Check if 400 is raise upon invalid manifest file."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/400/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='npm', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            with pytest.raises(Exception) as exception:
                sa.post_request()
            self.assertIs(exception.type, SAInvalidInputException)

    @patch('bayesian.utility.v2.stack_analyses.DependencyFinder.scan_and_find_dependencies',
           side_effect=Exception('Mock error'))
    def test_sa_invalid_manifest_file_unknown_error(self, _mock_depfinder):
        """Check if 400 is raise upon invalid manifest file."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/400/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='npm', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            with pytest.raises(Exception) as exception:
                sa.post_request()
            self.assertIs(exception.type, SAInvalidInputException)

    def test_sa_mismatch_manifest_file_and_ecosystem(self):
        """Check if 400 is raise upon mismatch between manifest file content and ecosystem type."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/202/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            with pytest.raises(Exception) as exception:
                sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                           ecosystem='pypi', show_transitive=True)
                sa = StackAnalyses(sa_post_request)
                sa.post_request()
            self.assertIs(exception.type, ValidationError)

    @patch('bayesian.utility.v2.stack_analyses.g')
    @patch('bayesian.utility.v2.stack_analyses.BackboneServer.post_aggregate_request',
           side_effect=BackboneServerException('Mock error'))
    def test_sa_backbone_error(self, _aggregate_request, _g):
        """Check if 500 is raise upon invalid response from backbone server."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/202/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='npm', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            with pytest.raises(Exception) as exception:
                sa.post_request()
            self.assertIs(exception.type, BackboneServerException)

    @patch('bayesian.utility.v2.stack_analyses.g')
    @patch('bayesian.utility.v2.stack_analyses.RdbAnalyses.save_post_request',
           side_effect=RDBSaveException('Mock exception'))
    def test_sa_rdb_error(self, _post_request, _g):
        """Check if 500 is raise upon request save failure."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/202/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='npm', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            with pytest.raises(Exception) as exception:
                sa.post_request()
            self.assertIs(exception.type, RDBSaveException)

    @patch('bayesian.utility.v2.stack_analyses.g')
    @patch('bayesian.utility.v2.stack_analyses.RdbAnalyses.save_post_request', side_effect=None)
    def test_sa_success(self, _post_request, _g):
        """Success stack analyses flow."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/202/npmlist.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='npmlist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='npm', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            response = sa.post_request()
            self.assertIsInstance(response, dict)
            self.assertIn('status', response)
            self.assertEqual(response['status'], 'success')
            self.assertIn('id', response)

    def test_get_flat_dependency_tree(self):
        """Test Get Flat Dependency tree."""
        with open(str(Path(__file__).parent.parent.parent) +
                  '/data/manifests/golist2.json', 'rb') as fp:
            fs = FileStorage(stream=fp, filename='golist.json')
            sa_post_request = StackAnalysesPostRequest(manifest=fs, file_path='/tmp/bin',
                                                       ecosystem='golang', show_transitive=True)
            sa = StackAnalyses(sa_post_request)
            sa._manifest_file_info = {
                'filename': sa.params.manifest.filename,
                'filepath': sa.params.file_path,
                'content': sa.params.manifest.read().decode('utf-8')
            }
            save_in_db, packages = sa._get_flat_dependency_tree()
            assert isinstance(save_in_db, dict)
            assert isinstance(save_in_db['result'], list)
            assert isinstance(save_in_db['result'][0]['details'], list)
            assert isinstance(save_in_db['result'][0]['details'][0], dict)
            assert isinstance(save_in_db['result'][0]['details'][0]['_resolved'], list)
            assert isinstance(save_in_db['result'][0]['details'][0]['_resolved'], list)
            assert isinstance(save_in_db['result'][0]['details'][0]['_resolved'][0], dict)
            assert save_in_db['result'][0]['details'][0]['_resolved'][0]['package'], \
                'github.com/thoughtworks/talisman'
            assert save_in_db['result'][0]['details'][0]['_resolved'][0]['version'], '0.3.3'
            assert isinstance(save_in_db['result'][0]['details'][0]['_resolved'][0]['deps'], list)
            assert save_in_db['result'][0]['details'][0]['_resolved'][0]['deps'][0]['package'], \
                'github.com/hashicorp/vault/vault'
            assert isinstance(packages, list)
