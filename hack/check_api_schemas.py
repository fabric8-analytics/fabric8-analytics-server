#!/usr/bin/env python3
"""Check API endpoints of local instance are schema compliant"""
import requests
import json
import jsonschema
import os.path
from urllib.parse import quote as quoteurl

_LOCAL_API_ENDPOINT = "http://localhost:32000/api/v1/analyses/"


def _get_analysis(api_url, ecosystem, component, version):
    component_path = quoteurl(component, safe="")
    analysis_url = os.path.join(api_url, ecosystem, component_path, version)
    analysis = requests.get(analysis_url)
    if analysis.status_code != 200:
        return None
    return analysis.json()


def get_analysis(analysis_info):
    return _get_analysis(_LOCAL_API_ENDPOINT,
                         analysis_info["ecosystem"],
                         analysis_info["package"],
                         analysis_info["version"])


if __name__ == "__main__":
    # Only the component analysis API has a defined schema for now
    api_file = "../schemas/generated/component-analysis-v1-0-0.schema.json"
    with open(api_file) as f:
        api_schema = json.load(f)

    components = requests.get(_LOCAL_API_ENDPOINT)
    components.raise_for_status()

    # Check each result in the local server validates against the schema
    for truncated_result in components.json()["items"]:
        jsonschema.validate(get_analysis(truncated_result), api_schema)
