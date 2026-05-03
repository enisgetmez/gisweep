"""Unit tests for client-side GIS library fingerprinting."""

from __future__ import annotations

import pytest

from gisweep.discovery.library_detect import (
    DetectedLibrary,
    classify_endpoint,
    detect_from_globals,
    detect_from_url,
    merge,
)


@pytest.mark.parametrize(
    ("url", "expected_name", "expected_version"),
    [
        ("https://unpkg.com/leaflet@1.7.1/dist/leaflet.css", "leaflet", "1.7.1"),
        ("https://unpkg.com/leaflet/dist/leaflet.js", None, None),
        ("https://unpkg.com/ol@6.5.0/build/ol.css", "openlayers", "6.5.0"),
        (
            "https://cdn.jsdelivr.net/npm/openlayers-9.2.0/build/ol.js",
            "openlayers",
            "9.2.0",
        ),
        (
            "https://cdn.jsdelivr.net/npm/mapbox-gl@2.0.0/dist/mapbox-gl.js",
            "mapbox-gl",
            "2.0.0",
        ),
        ("https://js.arcgis.com/4.27/", "arcgis-js-api", "4.27"),
    ],
)
def test_detect_from_url(url: str, expected_name: str | None, expected_version: str | None) -> None:
    hit = detect_from_url(url)
    if expected_name is None:
        assert hit is None
    else:
        assert hit is not None
        assert hit.name == expected_name
        assert hit.version is None or hit.version.startswith(expected_version or "")


def test_detect_from_url_handles_versioned_subpath() -> None:
    hit = detect_from_url("https://example.com/cesium-1.95.0/Cesium.js")
    assert hit is not None
    assert hit.name == "cesium"
    assert hit.version == "1.95.0"


def test_detect_from_globals_filters_nulls() -> None:
    probe = {
        "leaflet": "1.9.4",
        "openlayers": None,
        "mapbox-gl": "2.13.0",
        "cesium": None,
        "arcgis-js-api": None,
    }
    libs = detect_from_globals(probe)
    names = {lib.name for lib in libs}
    assert names == {"leaflet", "mapbox-gl"}
    assert all(lib.source == "global" for lib in libs)


def test_merge_dedupes_by_name_and_version() -> None:
    libs = [
        DetectedLibrary("leaflet", "1.9.4", "global", "L.version=1.9.4"),
        DetectedLibrary(
            "leaflet", "1.9.4", "url", "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"
        ),
        DetectedLibrary("openlayers", "6.5.0", "url", "https://unpkg.com/ol@6.5.0/"),
    ]
    merged = merge(libs)
    assert len(merged) == 2
    assert merged[0].source == "global"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.example/arcgis/rest/services/Foo/FeatureServer/0", "arcgis_rest"),
        ("https://x.example/server/rest/services/Foo/MapServer", "arcgis_rest"),
        ("https://x.example/arcgis/admin", "arcgis_admin"),
        ("https://x.example/?SERVICE=WMS&REQUEST=GetCapabilities", "ogc_wms"),
        ("https://api.mapbox.com/styles/v1/mapbox/streets-v11", "mapbox_api"),
        ("https://maps.googleapis.com/maps/api/js?key=AIza", "google_maps_api"),
        ("https://x.example/static/style.css", None),
        ("https://tile.openstreetmap.org/3/4/5.png", "tile_xyz"),
    ],
)
def test_classify_endpoint(url: str, expected: str | None) -> None:
    assert classify_endpoint(url) == expected
