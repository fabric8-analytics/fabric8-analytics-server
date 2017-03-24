#!/usr/bin/env python3
"""Script to validate draft schemas against example metadata"""

from pathlib import Path

_REPO_DIR = Path().resolve().parents[2]
_SERVER_DIR = _REPO_DIR / "server"
API_SCHEMA_DIR = _SERVER_DIR / "schemas" / "generated"
_WORKERS_DIR = _REPO_DIR / "lib" / "cucoslib" / "workers"
ANALYSIS_SCHEMA_DIR = _WORKERS_DIR / "schemas" / "generated"

ANALYSIS_SCHEMAS = {
    "crypto_algorithms":"crypto_algorithms-v1-0-0.schema.json",
    "security_issues": "security_issues-v1-0-0.schema.json",
    "source_licenses":"license-worker-v2-0-0.schema.json",
}

if __name__ == "__main__":
    import json
    import jsonschema

    schemas = {}
    for key, schema_file in ANALYSIS_SCHEMAS.items():
        with (ANALYSIS_SCHEMA_DIR / schema_file).open() as f:
            schemas[key] = json.load(f)

    data_dir = Path(__file__).parent / "data"
    examples = data_dir.glob("**/*.json")
    for scan_result in examples:
        print("Checking", scan_result)
        with scan_result.open() as f:
            scan_data = json.load(f)
            analyses = scan_data.get("analyses")
            if analyses is None:
                print("  No analysis data, skipping")
                continue
            for key, analysis in analyses.items():
                analysis.pop("_release", None)
                analysis.pop("schema", None)
            for key, schema in schemas.items():
                analysis = analyses[key]
                jsonschema.validate(analysis, schemas[key])

