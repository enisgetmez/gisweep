"""CVE database types, loader, and version-range matcher.

Every consumer (server-side ARC-015, client-side WEB-007..010) reads from this
single in-memory store. The on-disk format is JSON so it can be regenerated
non-interactively by ``scripts/refresh_cve_db.py``.

Schema (``cve_db.json``)::

    {
      "schema_version": 1,
      "generated_at": "<iso8601>",
      "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
      "products": {
        "esri:arcgis_server": [
          {
            "cve_id": "CVE-YYYY-NNNNN",
            "summary": "Short description.",
            "severity": "high",
            "cvss_score": 7.5,
            "cvss_vector": "AV:N/...",
            "published": "2024-...",
            "references": ["https://nvd.nist.gov/..."],
            "ranges": [
              {"introduced": null, "fixed": "10.9.1"},
              {"introduced": "11.0", "fixed": "11.2"}
            ]
          }
        ]
      }
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version


class CveSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Half-open ``[introduced, fixed)`` interval, or an exact-version match.

    ``introduced`` is the first vulnerable version (inclusive); ``None`` means
    "from the beginning of time". ``fixed`` is the first patched version
    (exclusive); ``None`` means "no fix announced yet". A version is *in
    range* iff ``introduced <= v < fixed``.

    If ``exact`` is set the other two fields are ignored and the range
    matches only that one version. NVD encodes most ArcGIS-era CVEs this way
    by listing a specific affected CPE rather than a half-open range.
    """

    introduced: str | None
    fixed: str | None
    exact: str | None = None

    def contains(self, version: str) -> bool:
        target = _try_version(version)
        if target is None:
            return False
        if self.exact is not None:
            exact = _try_version(self.exact)
            return exact is not None and target == exact
        if self.introduced is None and self.fixed is None:
            # an unconstrained range would match everything; treat as no-op so
            # records lacking version metadata never fire false positives.
            return False
        if self.introduced is not None:
            lo = _try_version(self.introduced)
            if lo is None or target < lo:
                return False
        if self.fixed is not None:
            hi = _try_version(self.fixed)
            if hi is None or target >= hi:
                return False
        return True


@dataclass(frozen=True, slots=True)
class CveRecord:
    cve_id: str
    summary: str
    severity: CveSeverity
    cvss_score: float | None
    cvss_vector: str | None
    published: datetime | None
    references: tuple[str, ...]
    ranges: tuple[VersionRange, ...]

    def affects(self, version: str) -> bool:
        if not self.ranges:
            return False
        return any(r.contains(version) for r in self.ranges)


@dataclass(frozen=True, slots=True)
class CveDatabase:
    schema_version: int
    generated_at: datetime | None
    source: str | None
    products: dict[str, tuple[CveRecord, ...]] = field(default_factory=dict)

    def for_product(self, product_key: str) -> tuple[CveRecord, ...]:
        return self.products.get(product_key, ())

    def matching(self, product_key: str, version: str) -> list[CveRecord]:
        return [record for record in self.for_product(product_key) if record.affects(version)]

    def is_empty(self) -> bool:
        return all(not records for records in self.products.values())


def matches_range(version: str, ranges: list[VersionRange]) -> bool:
    return any(r.contains(version) for r in ranges)


@lru_cache(maxsize=1)
def get_cve_database() -> CveDatabase:
    text = files("gisweep.data").joinpath("cve_db.json").read_text(encoding="utf-8")
    return _parse_database(json.loads(text))


def load_database_from_path(path: Path) -> CveDatabase:
    return _parse_database(json.loads(Path(path).read_text(encoding="utf-8")))


def _parse_database(raw: dict[str, Any]) -> CveDatabase:
    products_in: dict[str, list[dict[str, Any]]] = raw.get("products") or {}
    products: dict[str, tuple[CveRecord, ...]] = {
        key: tuple(_parse_record(record) for record in records)
        for key, records in products_in.items()
    }
    generated_at = _parse_datetime(raw.get("generated_at"))
    return CveDatabase(
        schema_version=int(raw.get("schema_version") or 1),
        generated_at=generated_at,
        source=raw.get("source"),
        products=products,
    )


def _parse_record(raw: dict[str, Any]) -> CveRecord:
    severity_raw = str(raw.get("severity") or "none").lower()
    try:
        severity = CveSeverity(severity_raw)
    except ValueError:
        severity = CveSeverity.NONE
    return CveRecord(
        cve_id=str(raw["cve_id"]),
        summary=str(raw.get("summary") or ""),
        severity=severity,
        cvss_score=_parse_float(raw.get("cvss_score")),
        cvss_vector=raw.get("cvss_vector"),
        published=_parse_datetime(raw.get("published")),
        references=tuple(str(x) for x in raw.get("references") or ()),
        ranges=tuple(_parse_range(r) for r in raw.get("ranges") or ()),
    )


def _parse_range(raw: dict[str, Any]) -> VersionRange:
    return VersionRange(
        introduced=raw.get("introduced"),
        fixed=raw.get("fixed"),
        exact=raw.get("exact"),
    )


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _try_version(value: str) -> Version | None:
    try:
        return Version(_normalize(value))
    except InvalidVersion:
        return None


def _normalize(version: str) -> str:
    """packaging.version is strict about pre-release notation; ArcGIS uses
    ``10.9.1`` style which packaging accepts. Trim trailing tokens like
    ``-beta`` that some NVD entries carry."""
    cleaned = version.strip()
    for sep in ("-", "+", " "):
        if sep in cleaned:
            cleaned = cleaned.split(sep, 1)[0]
    return cleaned
