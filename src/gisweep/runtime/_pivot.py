"""Helpers for the ``gisweep scan`` web → arcgis/ogc pivot.

The web crawler captures every request the page made. When it spots an
ArcGIS REST or OGC (GeoServer / MapServer / QGIS) endpoint we want to
hand that endpoint to the matching native scanner — but only when the
endpoint sits on the same registrable domain as the page the operator
asked us to scan. That guard keeps third-party tile / API hosts (Google
Maps, Mapbox, public basemap services) out of the pivot loop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True, slots=True)
class PivotTarget:
    """A normalized service root extracted from web-crawler traffic."""

    kind: str  # "arcgis" | "ogc"
    url: str  # service root ready to feed into the runtime
    sample: str  # one of the original URLs that produced this pivot, for logging


_ARCGIS_ROOT_RE = re.compile(
    r"^(?P<root>.*?/(?:arcgis|server)/rest)(?:/services(?:/.*)?)?(?:[?#].*)?$",
    re.IGNORECASE,
)
_GEOSERVER_ROOT_RE = re.compile(
    r"^(?P<root>.*?/geoserver(?:-cloud)?)(?:/.*)?(?:[?#].*)?$",
    re.IGNORECASE,
)
_MAPSERVER_ROOT_RE = re.compile(
    r"^(?P<root>.*?/cgi-bin/mapserv)(?:[?#].*)?$",
    re.IGNORECASE,
)


def normalize_pivot(url: str) -> PivotTarget | None:
    """Return a ``PivotTarget`` (kind + canonical service root) for *url*, or
    ``None`` when the URL does not map to a scannable GIS endpoint."""

    if (m := _ARCGIS_ROOT_RE.match(url)) is not None:
        root = f"{m.group('root')}/services"
        return PivotTarget(kind="arcgis", url=root, sample=url)

    if (m := _GEOSERVER_ROOT_RE.match(url)) is not None:
        return PivotTarget(kind="ogc", url=m.group("root"), sample=url)

    if (m := _MAPSERVER_ROOT_RE.match(url)) is not None:
        return PivotTarget(kind="ogc", url=m.group("root"), sample=url)

    # SERVICE=WMS / SERVICE=WFS query parameter without /geoserver/ in path —
    # treat the path-less URL up to the query string as the OGC service root.
    if re.search(r"[?&]service=(?:wms|wfs|wcs|wmts)", url, re.IGNORECASE):
        split = urlsplit(url)
        root = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        return PivotTarget(kind="ogc", url=root, sample=url)

    return None


def extract_pivots(
    urls: list[str],
    *,
    base_url: str,
) -> list[PivotTarget]:
    """Pull canonical pivot targets out of a list of captured URLs.

    Returns a deduplicated list sorted by kind+url, restricted to URLs that
    share the same registrable domain as *base_url*. Subdomains of the same
    registrable domain are kept (most municipalities run their GeoServer on
    a sibling subdomain like ``geoserver.example.bel.tr`` next to
    ``portal.example.bel.tr``).
    """
    base_domain = registrable_domain(base_url)
    out: dict[tuple[str, str], PivotTarget] = {}
    for url in urls:
        if not _same_registrable_domain(url, base_domain):
            continue
        pivot = normalize_pivot(url)
        if pivot is None:
            continue
        key = (pivot.kind, pivot.url)
        if key not in out:
            out[key] = pivot
    return sorted(out.values(), key=lambda p: (p.kind, p.url))


def registrable_domain(url_or_host: str) -> str:
    """A pragmatic eTLD+1 extractor.

    We deliberately do NOT pull in :mod:`tldextract` to keep the dependency
    surface small. The heuristic covers the common municipal / ccTLD cases
    that gisweep targets:

    * Single-label TLDs (``.com``, ``.net``, ``.org``) → keep the last two
      labels.
    * Two-label public suffixes used in TR / UK / AU / JP (e.g. ``.bel.tr``,
      ``.gov.tr``, ``.co.uk``, ``.com.au``) → keep the last three labels.

    For anything more exotic we fall back to "last two labels", which over-
    matches occasionally but only ever causes us to *over-pivot* on a
    related host that shares an apex — never to leak across organisations.
    """
    host = url_or_host
    if "://" in host:
        host = urlsplit(url_or_host).hostname or ""
    host = host.lower().strip()
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= _MIN_LABELS_FOR_COMPOUND_TLD:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _COMPOUND_PUBLIC_SUFFIXES:
        return ".".join(parts[-3:])
    return last_two


_MIN_LABELS_FOR_COMPOUND_TLD = 2

_COMPOUND_PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
        # Turkish public-sector suffixes — the prime gisweep audience.
        "bel.tr",
        "gov.tr",
        "edu.tr",
        "k12.tr",
        "tsk.tr",
        "pol.tr",
        "org.tr",
        "com.tr",
        "net.tr",
        # A few common international compound suffixes.
        "co.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "gov.au",
        "edu.au",
        "co.jp",
        "ne.jp",
        "co.kr",
    }
)


def _same_registrable_domain(url: str, base_domain: str) -> bool:
    if not base_domain:
        return False
    return registrable_domain(url) == base_domain
