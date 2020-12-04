"""Tests for functions implemented in the license_extractor module."""

from unittest.mock import patch

from bayesian.__init__ import app
from bayesian.license_extractor import get_license_synonyms, extract_licenses


def setUp(self):
    """Set up tests."""
    self.app_context = app.app_context()
    self.app_context.push()


def tearDown(self):
    """Tear down tests."""
    self.app_context.pop()


def current_app_logger(_str):
    """Mock for the logger."""
    pass


def test_get_license_synonyms():
    """Test the function get_license_synonyms()."""
    # make sure the LRU cache is clear
    get_license_synonyms.cache.clear()
    result = get_license_synonyms()
    assert len(result) > 0
    assert "bsd" in result
    assert "gpl" in result

    # do the same thing (use LRU actually)
    result = get_license_synonyms()
    assert len(result) > 0
    assert "bsd" in result
    assert "gpl" in result


class _response:
    """A fake HTTP response."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


def mocked_requests_get(url):
    """Implement mocked function requests.get()."""
    assert url
    return _response(404, "Not Found!")


@patch("bayesian.license_extractor.get", side_effect=mocked_requests_get)
def test_get_license_synonyms_wrong_response(mocked_get):
    """Test the function get_license_synonyms()."""
    # make sure the LRU cache is clear
    get_license_synonyms.cache.clear()
    result = get_license_synonyms()
    assert not result
    assert mocked_get.called


def _check_extracted_license(result, expected_license):
    """Check the extracted license output."""
    assert result
    assert len(result) >= 1
    assert result[1] == expected_license


def test_extract_licenses():
    """Test the function extract_licenses()."""
    # TODO: reduce cyclomatic complexity
    # make sure the LRU cache is clear
    get_license_synonyms.cache.clear()
    get_license_synonyms()

    # text/string mode
    with open("/bayesian/tests/data/licenses/licenses.txt") as fin:
        result = extract_licenses([fin])
        _check_extracted_license(result, "bsd-new")

    # binary mode
    with open("/bayesian/tests/data/licenses/licenses.txt", "rb") as fin:
        result = extract_licenses([fin])
        _check_extracted_license(result, "bsd-new")

    # text/string mode
    with open("/bayesian/tests/data/licenses/licenses2.txt") as fin:
        result = extract_licenses([fin])
        _check_extracted_license(result, "gplv2")

    # binary mode
    with open("/bayesian/tests/data/licenses/licenses2.txt", "rb") as fin:
        result = extract_licenses([fin])
        _check_extracted_license(result, "gplv2")


@patch("bayesian.license_extractor.get_license_synonyms", return_value=None)
def test_extract_licenses_no_synonyms(mocked_function):
    """Test the function extract_licenses()."""
    # make sure the LRU cache is clear
    get_license_synonyms.cache.clear()
    result = extract_licenses([])
    assert not result
    assert mocked_function.called


def test_extract_licenses_wrong_file():
    """Test the function extract_licenses()."""
    # make sure the LRU cache is clear
    get_license_synonyms.cache.clear()
    get_license_synonyms()
    result = extract_licenses(["this-is-not-a-file"])
    assert not result


if __name__ == '__main__':
    # if possible, run the test from the command line
    test_get_license_synonyms()
    test_get_license_synonyms_wrong_response()
    test_extract_licenses()
    test_extract_licenses_no_synonyms()
    test_extract_licenses_wrong_file()
