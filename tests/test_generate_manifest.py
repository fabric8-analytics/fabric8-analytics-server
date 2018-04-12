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


if __name__ == '__main__':
    test_constructor()
    pass
