"""Snyk related response data enricher."""

from urllib.parse import quote
from typing import Dict, List


class Enricher:
    """Response data Enricher."""

    __ECOSYSTEM_SYNONYM = {
        "pypi": "pip",
    }

    def __init__(self, ecosystem: str, attribution: str, utm: str):
        """Create Enricher based on given attribution, utm and ecosystem."""
        assert attribution is not None
        assert utm is not None
        assert ecosystem is not None

        self.__attribution = attribution
        self.__utm = utm
        # use the given ecosystem if no synonym found.
        self.__ecosystem = self.__ECOSYSTEM_SYNONYM.get(ecosystem, ecosystem)

    def __append_utm_in_url(self, package: str, vuln: Dict) -> Dict:
        url = vuln.get("url")
        if url is not None:
            package = quote(package, safe="")
            utm = self.__utm.format(ecosystem=self.__ecosystem, package=package)
            vuln["url"] = f"{url}?{utm}"
        return vuln

    def __append_attribution_in_title(self, vuln: Dict) -> Dict:
        title = vuln.get("title")
        if title is not None:
            vuln["title"] = f"{title} {self.__attribution}"
        return vuln

    def add_attribution_with_utm(self, payload: List[Dict]) -> List[Dict]:
        """Update title and url based on attribution and utm params."""
        for item in payload:
            package = item.get("package")
            for vuln in item.get("vulnerability", []):
                self.__append_attribution_in_title(vuln)
                self.__append_utm_in_url(package, vuln)
        return payload
