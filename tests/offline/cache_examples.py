#!/usr/bin/env python3
"""Script to cache example metadata"""
from __future__ import print_function
import csv
import errno
import json
import sys
import os
import os.path
from itertools import takewhile
try:
    from itertools import ifilter as filter
except ImportError:
    pass # Assume Python 3 with lazy builtin filter
try:
    from urllib import quote as quoteurl
except ImportError:
    from urllib.parse import quote as quoteurl

# Assume requests is available
import requests

# File scraping assumptions:
#   - at least one blank line between tables
#   - tables start with "| Ecosystem"
#   - header separator row exists and starts with "| -"
#   - rows start with "|" with columns separated by "|"
#   - first 3 columns in rows are ecosystem/component name/component version
def _is_start_of_table(line):
    return line.startswith("| Ecosystem")
def _is_line_in_table(line):
    return line.startswith("|")
def _parse_component_row(row):
    return tuple(col.strip() for col in row.split("|")[1:4])

def _extract_components(page_text):
    iter_lines = iter(page_text.splitlines())
    components = set()
    for line in filter(_is_start_of_table, iter_lines):
        header_separator = next(iter_lines)
        if not header_separator.startswith("| -"):
            print("Malformed separator:", header_separator, file=sys.stderr)
        for line in takewhile(_is_line_in_table, iter_lines):
            components.add(_parse_component_row(line))
    return sorted(components)

def _scrape_components(component_url):
    page = requests.get(component_url)
    page.raise_for_status()
    return _extract_components(page.text)

# Metadata retrieval assumptions
#   - analyses are at <api_url>/<ecosystem>/<component>/<version>
#   - analyses can be retrieved without authentication
#   - analyses will be available for all listed components
def _get_analysis(api_url, ecosystem, component, version):
    component_path = quoteurl(component, safe="")
    analysis_url = os.path.join(api_url, ecosystem, component_path, version)
    analysis = requests.get(analysis_url)
    if analysis.status_code != 200:
        return None
    return analysis.json()

def cache_metadata(components, api_url, destdir):
    print("Caching {0} metadata in {1}".format(api_url, destdir))
    for ecosystem, component, version in components:
        print("Caching {0} metadata for {1}({2})".format(ecosystem,
                                                         component,
                                                         version))
        analysis = _get_analysis(api_url, ecosystem, component, version)
        if analysis is None:
            print("  <Analysis not available>")
        elif "finished_at" not in analysis or analysis["finished_at"] is None:
            print("  <Analysis in progress>")
        else:
            component_dir = os.path.join(destdir, ecosystem, component)
            try:
                os.makedirs(component_dir)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
            version_path = os.path.join(component_dir, version) + ".json"
            # Strip variable elements
            analysis.pop("access_count")
            analysis.pop("started_at")
            analysis.pop("finished_at")
            # Cache stable elements of scan
            with open(version_path, "w") as f:
                json.dump(analysis, f, indent=2, sort_keys=True)
            print("  <{0}>".format(version_path))

def main(args):
    # Use first arg as API URL if given, otherwise default to cucos-01
    try:
        api_url = args[1]
    except IndexError:
        api_url = "http://localhost:32000/api/v1/analyses/"
    # Use second arg to retrieve package list if given, otherwise local CSV
    this_dir = os.path.dirname(__file__)
    pkg_list_name = os.path.join(this_dir, "package-list.csv")
    try:
        component_url = args[2]
    except IndexError:
        with open(pkg_list_name) as f:
            components = [tuple(row) for row in csv.reader(f)]
    else:
        components = _scrape_components(component_url)
        with open(pkg_list_name, "w") as f:
            csv.writer(f).writerows(components)
    destdir = os.path.join(this_dir, "data")
    cache_metadata(components, api_url, destdir)
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
