"""Tests for snyk enricher which adds attribution and utm params."""
from bayesian.utility.snyk import Enricher


def test_enricher_construction():
    """Test obj constrution."""
    assert Enricher(ecosystem="pypi", attribution="", utm="") is not None


def test_enricher_with_empty_input_array():
    """Test obj constrution with empty payload."""
    enricher = Enricher(ecosystem="pypi", attribution="(hello world)", utm="utm")
    result = enricher.add_attribution_with_utm([])
    assert [] == result


def test_enricher_with_empty_input_array_dict():
    """Test obj constrution with empty payload."""
    enricher = Enricher(ecosystem="pypi", attribution="(hello world)", utm="utm")
    result = enricher.add_attribution_with_utm([{}])
    assert [{}] == result


def test_enricher_with_valid_title():
    """Test obj constrution with valid title."""
    enricher = Enricher(ecosystem="pypi", attribution="(hello world)", utm="utm")
    result = enricher.add_attribution_with_utm([{"vulnerability": [{"title": "foo"}]}])
    assert [{"vulnerability": [{"title": "foo (hello world)"}]}] == result


def test_enricher_with_valid_titles():
    """Test obj constrution with valid titles."""
    enricher = Enricher(ecosystem="pypi", attribution="(hello world)", utm="utm")
    result = enricher.add_attribution_with_utm(
        [{"vulnerability": [{"title": "foo"}, {"title": "bar"}]}]
    )
    assert [
        {
            "vulnerability": [
                {"title": "foo (hello world)"},
                {"title": "bar (hello world)"},
            ]
        }
    ] == result


def test_enricher_with_valid_url():
    """Test obj constrution with valid title and url."""
    enricher = Enricher(
        ecosystem="pypi",
        attribution="(hello world)",
        utm="u_m=P&u_s=RH&u_c=2021&utm_content=vuln/{ecosystem}:{package}",
    )
    result = enricher.add_attribution_with_utm(
        [
            {
                "package": "foo:pkg",
                "vulnerability": [{"title": "foo", "url": "http://foo"}],
            },
            {
                "package": "bar:pkg",
                "vulnerability": [{"title": "bar", "url": "http://bar"}],
            },
        ]
    )
    assert [
        {
            "package": "foo:pkg",
            "vulnerability": [
                {
                    "title": "foo (hello world)",
                    "url": "http://foo?u_m=P&u_s=RH&u_c=2021&utm_content=vuln/pip:foo%3Apkg",
                },
            ],
        },
        {
            "package": "bar:pkg",
            "vulnerability": [
                {
                    "title": "bar (hello world)",
                    "url": "http://bar?u_m=P&u_s=RH&u_c=2021&utm_content=vuln/pip:bar%3Apkg",
                },
            ],
        },
    ] == result
