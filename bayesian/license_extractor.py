#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""License extractor utility functions."""

from .default_config import LIC_SYNONYMS_URL
from requests import get
from collections import defaultdict
from lru import lru_cache_function
from flask import current_app
from datetime import datetime as dt


# caching response for 24 hours
@lru_cache_function(max_size=2048, expiration=60 * 60 * 24)
def get_license_synonyms():
    """Fetch all the license sysnonyms from license anlysis github repo."""
    resp = get(LIC_SYNONYMS_URL)
    if resp.status_code == 200:
        current_app.logger.info(
            "{} Succefully fetched license synonyms".format(dt.now()))
        return resp.json()
    else:
        current_app.logger.error("{tm} Unable to fetch license synonyms, STATUS_CODE:{cd}".format(
            tm=dt.now(), cd=resp.status_code))
        return {}


def extract_licenses(license_files):
    """Extract license name from the given license files."""
    # TODO: reduce cyclomatic complexity
    lic_syn = get_license_synonyms()
    response = dict()
    if lic_syn:
        for f_no, _file in enumerate(license_files, 1):
            license_key = None
            try:
                # remove all the unnecessary chars ',', \n, space
                content = _file.read()
                if isinstance(content, (bytes, bytearray)):
                    content = content.decode('utf-8')
                content = ' '.join(content.split())
                content = content.replace(',', '').lower()
                _result = defaultdict(list)
                for lic in lic_syn:
                    license = lic.replace(',', '').lower()
                    # find the license names with their position in file content
                    index = content.find(license)
                    if index != -1:
                        # condition to check that license name is not a substring of a word
                        # ex: limit contains MIT as substring
                        if ((index == 0 or not content[index - 1].isalpha()) and
                            (index + len(license) == len(content) or not
                             content[index + len(license)].isalpha())):
                            _result[index].append(lic)
                if _result:
                    # get the name of the license which comes first in the file.
                    _temp = _result.get(min(_result.keys()))
                    if _temp:
                        license_key = max(_temp, key=len)
                response[f_no] = lic_syn.get(license_key, 'unknown')
            except Exception as e:
                current_app.logger.error('{time} {msg}'.format(time=dt.now(), msg=str(e)))
    else:
        get_license_synonyms.cache.clear()
    return response
