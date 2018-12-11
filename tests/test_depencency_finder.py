"""Tests for classes from depencency_finder module."""

from bayesian.dependency_finder import DependencyFinder
from pathlib import Path


def test_scan_and_find_dependencies():
    """Test scan_and_find_dependencies function."""
    manifests = [{
        "filename": "npm-list.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/manifests/npm-list.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("npm", manifests)
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "body-parser"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 2


def test_scan_and_find_dependencies_pypi():
    """Test scan_and_find_dependencies function for pypi."""
    manifests = [{
        "filename": "pylist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/manifests/pylist.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("pypi", manifests)
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == "django"
    assert len(res['result'][0]['details'][0]['_resolved'][0]['deps']) == 1


def test_scan_and_find_dependencies_golang():
    """Test scan_and_find_dependencies function for golang."""
    manifests = [{
        "filename": "golist.json",
        "filepath": "/bin/local",
        "content": open(str(Path(__file__).parent / "data/manifests/golist.json")).read()
    }]
    res = DependencyFinder().scan_and_find_dependencies("golang", manifests)
    assert "result" in res
    assert res['result'][0]['details'][0]['_resolved'][0]['package'] == \
        "github.com/asaskevich/govalidator"


if __name__ == '__main__':
    test_scan_and_find_dependencies()
    test_scan_and_find_dependencies_pypi()
