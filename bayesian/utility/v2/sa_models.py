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
from pydantic import Field, BaseModel, validator
from werkzeug.datastructures import FileStorage
from bayesian.utils import resolved_files_exist


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

    @validator('manifest')
    def manifest_file_name_must_be_valid(v):
        """Check if manifest file name is in supported list."""
        if not resolved_files_exist(v.filename):
            raise ValueError('Error processing request. Manifest is missing its value {} is '
                             'invalid / not supported'.format(v.filename))
        return v
