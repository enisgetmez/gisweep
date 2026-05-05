"""Unit tests for the scan-pivot helpers (web → arcgis/ogc orchestration)."""

from __future__ import annotations

import pytest

from gisweep.runtime._pivot import (
    extract_pivots,
    normalize_pivot,
    registrable_domain,
)


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://example.com/x", "example.com"),
            ("https://www.example.com/x", "example.com"),
            ("https://api.deep.example.com/x", "example.com"),
            ("https://portal.example.bel.tr/Harita", "example.bel.tr"),
            ("https://geoserver.example.bel.tr/geoserver", "example.bel.tr"),
            ("https://cbs.example.gov.tr/arcgis", "example.gov.tr"),
            ("https://shop.example.co.uk/x", "example.co.uk"),
            ("example.com", "example.com"),
            ("a.b.example.gov.tr", "example.gov.tr"),
            ("", ""),
        ],
    )
    def test_extracts_apex_for_common_suffixes(self, url: str, expected: str) -> None:
        assert registrable_domain(url) == expected


class TestNormalizePivot:
    @pytest.mark.parametrize(
        ("url", "kind", "expected_root"),
        [
            (
                "https://x.gov/arcgis/rest/services/Foo/MapServer/0/query?where=1=1",
                "arcgis",
                "https://x.gov/arcgis/rest/services",
            ),
            (
                "https://x.gov/server/rest/services/Foo/FeatureServer/0",
                "arcgis",
                "https://x.gov/server/rest/services",
            ),
            (
                "https://x.gov/geoserver/foo/wms?service=WMS&request=GetMap&layers=l",
                "ogc",
                "https://x.gov/geoserver",
            ),
            (
                "https://x.gov/geoserver-cloud/wms?service=WMS&request=GetMap",
                "ogc",
                "https://x.gov/geoserver-cloud",
            ),
            (
                "https://x.gov/cgi-bin/mapserv?map=foo.map",
                "ogc",
                "https://x.gov/cgi-bin/mapserv",
            ),
            (
                # No /geoserver/ in path, but SERVICE=WMS query param still
                # identifies it as an OGC service. Pivot to the path root.
                "https://x.gov/maps/wms?SERVICE=WMS&REQUEST=GetCapabilities",
                "ogc",
                "https://x.gov/maps/wms",
            ),
        ],
    )
    def test_extracts_canonical_root(self, url: str, kind: str, expected_root: str) -> None:
        pivot = normalize_pivot(url)
        assert pivot is not None
        assert pivot.kind == kind
        assert pivot.url == expected_root

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.mapbox.com/styles/v1/mapbox/streets-v11",
            "https://maps.googleapis.com/maps/api/js?key=AIza...",
            "https://x.gov/static/main.js",
            "https://x.gov/index.html",
        ],
    )
    def test_returns_none_for_non_gis_urls(self, url: str) -> None:
        assert normalize_pivot(url) is None


class TestExtractPivots:
    def test_dedupes_repeated_endpoints(self) -> None:
        urls = [
            "https://gis.x.gov/arcgis/rest/services/Foo/MapServer/0/query",
            "https://gis.x.gov/arcgis/rest/services/Foo/MapServer/1/query",
            "https://gis.x.gov/arcgis/rest/services/Bar/FeatureServer/0",
        ]
        out = extract_pivots(urls, base_url="https://www.x.gov/portal")
        assert len(out) == 1
        assert out[0].kind == "arcgis"
        assert out[0].url == "https://gis.x.gov/arcgis/rest/services"

    def test_keeps_distinct_kinds(self) -> None:
        urls = [
            "https://gis.x.gov/arcgis/rest/services/Foo/MapServer/0/query",
            "https://gis.x.gov/geoserver/foo/wms?service=WMS&request=GetMap",
        ]
        out = extract_pivots(urls, base_url="https://www.x.gov/portal")
        kinds = {p.kind for p in out}
        assert kinds == {"arcgis", "ogc"}

    def test_drops_third_party_hosts(self) -> None:
        urls = [
            "https://gis.x.gov/arcgis/rest/services/Foo/MapServer/0",
            "https://gis.foreign-org.com/arcgis/rest/services/Bar/MapServer/0",
            "https://api.mapbox.com/styles/v1/foo",
        ]
        out = extract_pivots(urls, base_url="https://www.x.gov/portal")
        assert len(out) == 1
        assert "x.gov" in out[0].url
        # The mapbox + foreign-org URLs must NOT have produced a pivot.
        assert all("foreign-org" not in p.url for p in out)
        assert all("mapbox" not in p.url for p in out)

    def test_keeps_subdomains_of_same_apex(self) -> None:
        # Real-world municipal pattern: portal on one subdomain, GeoServer on
        # a sibling subdomain — both under the same registrable domain.
        urls = [
            "https://geoserver.example.bel.tr/geoserver/foo/wms?service=WMS",
        ]
        out = extract_pivots(urls, base_url="https://portal.example.bel.tr/Harita")
        assert len(out) == 1
        assert out[0].url == "https://geoserver.example.bel.tr/geoserver"
