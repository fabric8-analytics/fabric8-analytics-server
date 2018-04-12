"""Tests for classes from generate_manifest module."""

import pytest
from bayesian.generate_manifest import *


def test_constructor():
    """Test the constructor for the PomXMLTemplate class."""
    obj = PomXMLTemplate({})
    assert obj is not None

    payload = {
        "framework": "framework",
        "dependencies": "deps",
        "project": {
            "decription": "desc"
        }
    }
    obj = PomXMLTemplate(payload)
    assert obj is not None

    payload = {
        "framework": "framework",
        "dependencies": "deps",
        "project": {
            "decription": "desc",
            "options": {
                "group": "grp",
                "artifactId": "aid",
                "version": "1.0.0"
            }
        }
    }
    obj = PomXMLTemplate(payload)
    assert obj is not None


def test_attributes():
    """Test the content of PomXMLTemplate attributes."""
    obj = PomXMLTemplate({})
    assert obj._data == {}
    assert obj.root is not None
    assert obj.tree is not None


def test_add_framework():
    """Test the method add_framework()."""
    # should not fail
    obj = PomXMLTemplate({})
    obj.add_framework("")

    # should not fail
    obj = PomXMLTemplate({})
    obj.add_framework("xyzzy")

    obj = PomXMLTemplate({})
    obj.add_framework("springboot")
    assert obj._parent is not None

    obj = PomXMLTemplate({})
    obj.add_framework("vertx")
    assert obj._parent is not None

    obj = PomXMLTemplate({})
    obj.add_framework("wildfly")
    assert obj._parent is not None


def test_xml_string():
    """Test the method xml_string()."""
    payload = {
        "framework": "framework",
        "dependencies": "deps",
        "project": {
            "decription": "desc",
            "options": {
                "group": "grp",
                "artifactId": "aid",
                "version": "1.0.0"
            }
        }
    }
    obj = PomXMLTemplate(payload)
    result = obj.xml_string()
    assert result is not None


def test_add_dependencies():
    """Test the method add_dependencies()."""
    obj = PomXMLTemplate({})
    obj.add_framework("springboot")
    assert obj._parent is not None

    # should not fail
    obj.add_dependencies(None)
    obj.add_dependencies(["dependency1", "dependency2"])


if __name__ == '__main__':
    test_constructor()
    test_attributes()
    test_add_framework()
    test_add_dependencies()
    test_xml_string()
