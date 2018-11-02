"""Tests for classes from depencency_finder module."""

from unittest import TestCase, mock
from bayesian.dependency_finder import DependencyFinder
from pathlib import Path


@mock.patch("bayesian.dependency_finder.DependencyFinder.get_npm_dependencies")
def test_scan_and_find_dependencies(mocker):
    """Test scan_and_find_dependencies function."""
    mocker.return_value = "npm"
    manifests = [{}]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests)
    assert "npm" == res


content = {
            "dependencies": {
                "body-parser": {
                    "version": "1.18.2",
                    "dependencies": {
                        "debug": {
                            "version": "2.6.9",
                            "from": "debug@2.6.9",
                            "resolved": "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz",
                            "dependencies": {
                                "ms": {
                                    "version": "2.0.0",
                                    "from": "ms@2.0.0",
                                    "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"
                                }
                            }
                        }
                    }
                }
            }
        }


def test_get_npm_dependencies():
    """Test get_npm_dependencies function."""
    manifests = [{
        "filename": "npm-list.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/manifests/npm-list.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests)
    print(res)
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "body-parser"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 2


if __name__ == '__main__':
    test_scan_and_find_dependencies()
