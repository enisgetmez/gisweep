"""OGC web service discovery: WMS / WFS GetCapabilities probing + parsing.

Given a base URL, the enumerator probes a set of well-known endpoint patterns
(``/geoserver/wms``, ``/cgi-bin/mapserv``, ``?SERVICE=WMS&REQUEST=GetCapabilities``,
etc.), parses each successful XML response, and surfaces:

* the service kind (WMS, WFS) and protocol version,
* the server software + version inferred from the document,
* the exposed layer / feature-type list,
* a coarse op→authentication map for WFS (Transaction support, etc.).

XML is parsed via :mod:`defusedxml` so the scanner does not become a vector
itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from defusedxml import ElementTree as Det

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

    from gisweep.core.http import HttpClient


@dataclass(frozen=True, slots=True)
class OgcServerFingerprint:
    """Best-effort identification of the software behind an OGC endpoint."""

    software: (
        str  # canonical name: "geoserver" | "mapserver" | "qgis_server" | "deegree" | "unknown"
    )
    version: str | None
    raw_signature: str  # the substring matched, for evidence


@dataclass(frozen=True, slots=True)
class OgcLayerRef:
    name: str
    title: str | None
    queryable: bool


@dataclass(frozen=True, slots=True)
class OgcCapabilities:
    service: str  # "WMS" | "WFS"
    version: str
    endpoint_url: str
    fingerprint: OgcServerFingerprint
    layers: tuple[OgcLayerRef, ...]
    operations: frozenset[str] = field(default_factory=frozenset)
    raw_excerpt: str = ""


_DEFAULT_PATHS: tuple[str, ...] = (
    "geoserver/wms",
    "geoserver/wfs",
    "geoserver/ows",
    "wms",
    "wfs",
    "ows",
    "cgi-bin/mapserv",
    "mapserv",
)
_GET_CAPABILITIES_QUERIES: tuple[tuple[str, str], ...] = (
    ("WMS", "1.3.0"),
    ("WMS", "1.1.1"),
    ("WFS", "2.0.0"),
    ("WFS", "1.1.0"),
)
_RAW_EXCERPT_BYTES = 4096


class OgcEnumerator:
    def __init__(self, http: HttpClient, base_url: str) -> None:
        self._http = http
        self._base = base_url.rstrip("/")

    @property
    def base_url(self) -> str:
        return self._base

    async def probe(self, paths: Iterable[str] | None = None) -> AsyncIterator[OgcCapabilities]:
        """Yield one :class:`OgcCapabilities` per (endpoint, service) that
        responds with a parseable GetCapabilities document."""
        seen: set[tuple[str, str]] = set()
        candidates = list(self._candidate_endpoints(paths))
        for endpoint in candidates:
            for service, version in _GET_CAPABILITIES_QUERIES:
                url = self._with_capabilities_query(endpoint, service, version)
                try:
                    response = await self._http.get(url)
                except (httpx.HTTPError, OSError):
                    continue
                if not _looks_like_xml(response):
                    continue
                doc = _parse_capabilities(response.text, service)
                if doc is None:
                    continue
                key = (endpoint, doc["service"])
                if key in seen:
                    continue
                seen.add(key)
                yield OgcCapabilities(
                    service=doc["service"],
                    version=doc["version"],
                    endpoint_url=endpoint,
                    fingerprint=_fingerprint(response.text),
                    layers=tuple(_layer_from_dict(item) for item in doc["layers"]),
                    operations=frozenset(doc["operations"]),
                    raw_excerpt=response.text[:_RAW_EXCERPT_BYTES],
                )

    def _candidate_endpoints(self, paths: Iterable[str] | None) -> list[str]:
        chosen = paths if paths is not None else _DEFAULT_PATHS
        out: list[str] = [self._base]
        out.extend(f"{self._base}/{path.lstrip('/')}" for path in chosen)
        # de-duplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for url in out:
            if url not in seen:
                seen.add(url)
                unique.append(url)
        return unique

    @staticmethod
    def _with_capabilities_query(endpoint: str, service: str, version: str) -> str:
        split = urlsplit(endpoint)
        params = {"SERVICE": service, "VERSION": version, "REQUEST": "GetCapabilities"}
        return urlunsplit(
            (split.scheme, split.netloc, split.path, urlencode(params), split.fragment)
        )


# ---------- XML parsing helpers -----------------------------------------------


_GEOSERVER_VERSION_RE = re.compile(r"GeoServer\s+([0-9][0-9A-Za-z\._\-]*)")
_MAPSERVER_VERSION_RE = re.compile(r"MapServer\s+([0-9][0-9A-Za-z\._\-]*)")
_QGIS_VERSION_RE = re.compile(r"QGIS(?:\s+Server)?\s+([0-9][0-9A-Za-z\._\-]*)")
_DEEGREE_VERSION_RE = re.compile(r"deegree\s+([0-9][0-9A-Za-z\._\-]*)")


def _fingerprint(body: str) -> OgcServerFingerprint:  # noqa: PLR0911 -- one branch per supported product is the simplest expression
    if (m := _GEOSERVER_VERSION_RE.search(body)) is not None:
        return OgcServerFingerprint("geoserver", m.group(1), m.group(0))
    if "GeoServer" in body:
        return OgcServerFingerprint("geoserver", None, "GeoServer")
    if (m := _MAPSERVER_VERSION_RE.search(body)) is not None:
        return OgcServerFingerprint("mapserver", m.group(1), m.group(0))
    if "MapServer" in body:
        return OgcServerFingerprint("mapserver", None, "MapServer")
    if (m := _QGIS_VERSION_RE.search(body)) is not None:
        return OgcServerFingerprint("qgis_server", m.group(1), m.group(0))
    if (m := _DEEGREE_VERSION_RE.search(body)) is not None:
        return OgcServerFingerprint("deegree", m.group(1), m.group(0))
    return OgcServerFingerprint("unknown", None, "")


def _looks_like_xml(response: httpx.Response) -> bool:
    if response.status_code != 200:  # noqa: PLR2004
        return False
    content_type = response.headers.get("content-type", "").lower()
    if "xml" in content_type or "text/plain" in content_type:
        return True
    body = response.text.lstrip()
    return body.startswith("<?xml") or body.startswith("<")


def _parse_capabilities(xml_text: str, expected_service: str) -> dict[str, Any] | None:
    try:
        root = Det.fromstring(xml_text)
    except (Det.ParseError, ValueError):
        return None
    tag = _local_name(root.tag).lower()
    if "wms_capabilities" in tag or "wmt_ms_capabilities" in tag:
        if expected_service != "WMS":
            return None
        version = root.attrib.get("version", "")
        layers = _wms_layers(root)
        return {
            "service": "WMS",
            "version": version,
            "layers": layers,
            "operations": _wms_operations(root),
        }
    if "wfs_capabilities" in tag:
        if expected_service != "WFS":
            return None
        version = root.attrib.get("version", "")
        layers = _wfs_feature_types(root)
        return {
            "service": "WFS",
            "version": version,
            "layers": layers,
            "operations": _wfs_operations(root),
        }
    return None


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _iter_local(root: Any, name: str) -> list[Any]:
    return [el for el in root.iter() if _local_name(el.tag).lower() == name.lower()]


def _wms_layers(root: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for layer in _iter_local(root, "Layer"):
        name_el = next((c for c in layer if _local_name(c.tag).lower() == "name"), None)
        title_el = next((c for c in layer if _local_name(c.tag).lower() == "title"), None)
        if name_el is None or not (name_el.text or "").strip():
            continue
        out.append(
            {
                "name": (name_el.text or "").strip(),
                "title": (title_el.text or "").strip() if title_el is not None else None,
                "queryable": layer.attrib.get("queryable", "0") in {"1", "true"},
            }
        )
    return out


def _wms_operations(root: Any) -> set[str]:
    request_el = next(iter(_iter_local(root, "Request")), None)
    if request_el is None:
        return set()
    return {_local_name(child.tag) for child in request_el}


def _wfs_feature_types(root: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ft in _iter_local(root, "FeatureType"):
        name_el = next((c for c in ft if _local_name(c.tag).lower() == "name"), None)
        title_el = next((c for c in ft if _local_name(c.tag).lower() == "title"), None)
        if name_el is None or not (name_el.text or "").strip():
            continue
        out.append(
            {
                "name": (name_el.text or "").strip(),
                "title": (title_el.text or "").strip() if title_el is not None else None,
                "queryable": True,
            }
        )
    return out


def _wfs_operations(root: Any) -> set[str]:
    operations: set[str] = set()
    for op in _iter_local(root, "Operation"):
        name = op.attrib.get("name")
        if name:
            operations.add(name)
    for op in _iter_local(root, "OperationsMetadata"):
        for child in op.iter():
            if _local_name(child.tag).lower() == "operation":
                name = child.attrib.get("name")
                if name:
                    operations.add(name)
    return operations


def _layer_from_dict(spec: dict[str, Any]) -> OgcLayerRef:
    return OgcLayerRef(
        name=str(spec.get("name") or ""),
        title=spec.get("title"),
        queryable=bool(spec.get("queryable")),
    )
