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
"""Data model for Stack analyses API v2."""

from enum import Enum
from typing import Optional
from pydantic import Field, BaseModel, root_validator
from werkzeug.datastructures import FileStorage
from bayesian.utils import resolved_files_exist, get_ecosystem_from_manifest


class Ecosystem(str, Enum):
    """Supported ecosystem enumerations."""

    maven = 'maven'
    pypi = 'pypi'
    npm = 'npm'


class StackAnalysesPostRequest(BaseModel):
    """Stack anaylses POST request param model."""

    manifest: FileStorage
    file_path: str
    ecosystem: 'Ecosystem'
    show_transitive: Optional[bool] = Field(
        True,
        description='This is required to enable or disable the transitive support',
    )

    class Config:
        """Validation configuration for model."""

        # Override config to allow arbitoary type i.e., FileStorage.
        arbitrary_types_allowed = True

        # Min length of string should be 1 as '/' is a valid path
        min_anystr_length = 1

    @root_validator()
    def check_input_data(cls, values):  # noqa: V106 - Ignore 'cls' not used check
        """Validate input data for ecosystem and manifest file."""
        ecosystem, manifest = values.get('ecosystem'), values.get('manifest')

        if manifest is None:
            raise ValueError('Error processing request. Manifest is missing')

        if not resolved_files_exist(manifest.filename):
            raise ValueError('Error processing request. Manifest is missing its value {} is '
                             'invalid / not supported'.format(manifest.filename))

        ecosystem_from_manifest = get_ecosystem_from_manifest(manifest.filename)
        if ecosystem != ecosystem_from_manifest:
            raise ValueError('Error processing request. Manifest {} and ecosystem {} does '
                             'not match'.format(manifest.filename, ecosystem))

        return values
