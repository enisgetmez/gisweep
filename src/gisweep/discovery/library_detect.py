"""Client-side GIS library fingerprinting.

Two complementary detectors:

* ``DETECTORS`` — JavaScript expressions evaluated inside the page that read
  the canonical version global of each library (``window.L.version`` etc.).
* ``URL_PATTERNS`` — regex applied to network request URLs to recover the
  library name + version when it is loaded from a public CDN.

The runtime layer combines both signals into a deduplicated
:class:`DetectedLibrary` list per page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectedLibrary:
    name: str  # canonical: "leaflet" | "openlayers" | "mapbox-gl" | "cesium" | "arcgis-js-api"
    version: str | None
    source: str  # "global" | "url"
    evidence: str


JS_GLOBAL_PROBE = """() => {
  const has = (name) => typeof window[name] !== 'undefined' && window[name];
  const arcgis = has('esri') && window.esri.version
      ? window.esri.version
      : (has('esriConfig') && window.esriConfig.version) || null;
  return {
    leaflet: has('L') ? (window.L.version || null) : null,
    openlayers: has('ol') ? (window.ol.VERSION || null) : null,
    'mapbox-gl': has('mapboxgl') ? (window.mapboxgl.version || null) : null,
    cesium: has('Cesium') ? (window.Cesium.VERSION || null) : null,
    'arcgis-js-api': arcgis,
  };
}
"""


_URL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "leaflet",
        re.compile(r"/leaflet[@\-/](?P<version>\d+\.\d+(?:\.\d+)?)/", re.IGNORECASE),
    ),
    (
        "openlayers",
        re.compile(r"/(?:ol|openlayers)[@\-/](?P<version>\d+\.\d+(?:\.\d+)?)/", re.IGNORECASE),
    ),
    (
        "mapbox-gl",
        re.compile(r"/mapbox-gl[@\-/](?P<version>\d+\.\d+(?:\.\d+)?)/", re.IGNORECASE),
    ),
    (
        "cesium",
        re.compile(
            r"/cesium(?:js)?[@\-/](?P<version>\d+\.\d+(?:\.\d+)?)/",
            re.IGNORECASE,
        ),
    ),
    (
        "arcgis-js-api",
        re.compile(r"js\.arcgis\.com/(?P<version>\d+\.\d+(?:\.\d+)?)/", re.IGNORECASE),
    ),
)


def detect_from_url(url: str) -> DetectedLibrary | None:
    """Return a single library hit if the URL matches a known CDN/version pattern."""
    for name, pattern in _URL_PATTERNS:
        match = pattern.search(url)
        if match is not None:
            return DetectedLibrary(
                name=name,
                version=match.group("version"),
                source="url",
                evidence=url,
            )
    return None


def detect_from_globals(probe_result: dict[str, str | None]) -> list[DetectedLibrary]:
    """Convert the result of evaluating :data:`JS_GLOBAL_PROBE` into library hits."""
    out: list[DetectedLibrary] = []
    for name, version in probe_result.items():
        if version is None:
            continue
        out.append(
            DetectedLibrary(
                name=name,
                version=str(version),
                source="global",
                evidence=f"window.{_global_for(name)}.version={version}",
            )
        )
    return out


def merge(detected: list[DetectedLibrary]) -> list[DetectedLibrary]:
    """Deduplicate by ``(name, version)`` keeping the first occurrence."""
    seen: set[tuple[str, str | None]] = set()
    out: list[DetectedLibrary] = []
    for lib in detected:
        key = (lib.name, lib.version)
        if key in seen:
            continue
        seen.add(key)
        out.append(lib)
    return out


def _global_for(name: str) -> str:
    return {
        "leaflet": "L",
        "openlayers": "ol",
        "mapbox-gl": "mapboxgl",
        "cesium": "Cesium",
        "arcgis-js-api": "esri",
    }.get(name, name)


# Patterns for ArcGIS / OGC endpoints discovered from network traffic. Used by
# WEB-001 to surface the embedded-map data plane.
ENDPOINT_PATTERNS: dict[str, re.Pattern[str]] = {
    "arcgis_rest": re.compile(r"/(?:arcgis|server)/rest/services/", re.IGNORECASE),
    "arcgis_admin": re.compile(r"/(?:arcgis|server)/(?:admin|portaladmin)", re.IGNORECASE),
    "ogc_wms": re.compile(r"[?&]SERVICE=WMS", re.IGNORECASE),
    "ogc_wfs": re.compile(r"[?&]SERVICE=WFS", re.IGNORECASE),
    "mapbox_api": re.compile(r"://api\.mapbox\.com/", re.IGNORECASE),
    "google_maps_api": re.compile(r"://maps\.googleapis\.com/", re.IGNORECASE),
    "tile_xyz": re.compile(
        r"/\d+/\d+/\d+\.(?:png|pbf|jpg|jpeg|webp|mvt)(?:[?#].*)?$",
        re.IGNORECASE,
    ),
}


def classify_endpoint(url: str) -> str | None:
    for kind, pattern in ENDPOINT_PATTERNS.items():
        if pattern.search(url):
            return kind
    return None
