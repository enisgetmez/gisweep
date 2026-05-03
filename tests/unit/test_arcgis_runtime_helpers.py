"""Unit tests for runtime/arcgis.py URL normalization."""

from __future__ import annotations

import pytest

from gisweep.runtime.arcgis import normalize_rest_root


@pytest.mark.parametrize(
    ("input_url", "expected"),
    [
        # missing /services — auto-append
        ("https://x.example/arcgis/rest", "https://x.example/arcgis/rest/services"),
        ("https://x.example/arcgis/rest/", "https://x.example/arcgis/rest/services"),
        ("https://x.example/server/rest", "https://x.example/server/rest/services"),
        ("https://x.example/server/rest/", "https://x.example/server/rest/services"),
        # already correct
        (
            "https://x.example/arcgis/rest/services",
            "https://x.example/arcgis/rest/services",
        ),
        (
            "https://x.example/arcgis/rest/services/",
            "https://x.example/arcgis/rest/services",
        ),
        # subpath beyond services — leave alone, just strip trailing slash
        (
            "https://x.example/arcgis/rest/services/Foo/MapServer",
            "https://x.example/arcgis/rest/services/Foo/MapServer",
        ),
        # unrelated paths stay unchanged
        ("https://x.example/", "https://x.example"),
        ("https://x.example/arcgis", "https://x.example/arcgis"),
    ],
)
def test_normalize_rest_root(input_url: str, expected: str) -> None:
    assert normalize_rest_root(input_url) == expected
