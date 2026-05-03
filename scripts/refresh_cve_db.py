"""Regenerate ``src/gisweep/data/cve_db.json`` from NIST NVD.

Run::

    uv run python -m scripts.refresh_cve_db

This script hits the NVD CVE 2.0 API (https://services.nvd.nist.gov/rest/json/cves/2.0)
once per tracked CPE, normalizes results into the gisweep schema, and writes
the database file. It is intended for CI cron / contributor maintenance, not
for end-user runtime — checks read the bundled snapshot at scan time.

NVD recommends ≤50 requests / 30 seconds per IP. The script paces itself with
a 6-second delay between calls; pass ``--api-key`` for a higher limit.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "src" / "gisweep" / "data" / "cve_db.json"
USER_AGENT = "gisweep-refresh-cve-db/0.1.0 (+https://github.com/enisgetmez/gisweep)"

_MAX_RETRIES = 3
_CPE_VERSION_INDEX = 5
_CPE_MIN_FIELDS = 6


PRODUCTS: dict[str, list[str]] = {
    # ArcGIS server-side
    "esri:arcgis_server": ["cpe:2.3:a:esri:arcgis_server"],
    "esri:arcgis_api_for_javascript": ["cpe:2.3:a:esri:arcgis_api_for_javascript"],
    # Open-source OGC servers (each canonical key may aggregate multiple CPE
    # vendor strings used by NVD over time)
    "osgeo:geoserver": [
        "cpe:2.3:a:osgeo:geoserver",
        "cpe:2.3:a:geoserver:geoserver",
    ],
    "osgeo:mapserver": [
        "cpe:2.3:a:osgeo:mapserver",
        "cpe:2.3:a:mapserver:mapserver",
    ],
    "qgis:qgis": ["cpe:2.3:a:qgis:qgis"],
    "deegree:deegree": ["cpe:2.3:a:deegree:deegree"],
    "geonetwork-opensource:geonetwork": [
        "cpe:2.3:a:geonetwork-opensource:geonetwork",
        "cpe:2.3:a:geonetwork:geonetwork",
    ],
    # Client-side JS libraries (fingerprinted by the Phase 4 web crawler).
    # Verified against the NVD CPE dictionary (services.nvd.nist.gov/rest/json/cpes/2.0):
    #   - leafletjs:leaflet            ✓ tracked
    #   - cesium:cesiumjs              ✓ tracked (NOT cesiumgs:cesium)
    #   - openlayers, mapbox-gl-js     ✗ no formal CPE entry in NVD as of 2026-05;
    #                                    keep keys present so the product slots
    #                                    surface in 'gisweep checks list' and
    #                                    light up the day NVD adds them.
    "openlayers:openlayers": ["cpe:2.3:a:openlayers:openlayers"],
    "leafletjs:leaflet": ["cpe:2.3:a:leafletjs:leaflet"],
    "mapbox:mapbox-gl-js": [
        "cpe:2.3:a:mapbox:mapbox-gl-js",
        "cpe:2.3:a:mapbox:mapbox_gl_js",
    ],
    "cesium:cesiumjs": [
        "cpe:2.3:a:cesium:cesiumjs",
        "cpe:2.3:a:cesiumgs:cesium",  # historical fallback
    ],
}


def main() -> int:  # pragma: no cover -- network/IO entry point
    parser = argparse.ArgumentParser(description="Refresh gisweep CVE DB from NIST NVD")
    parser.add_argument("--api-key", default=None, help="Optional NVD API key.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--results-per-page", type=int, default=2000)
    parser.add_argument("--rate-delay", type=float, default=6.0)
    args = parser.parse_args()

    products = asyncio.run(
        _fetch_all(
            api_key=args.api_key,
            results_per_page=args.results_per_page,
            rate_delay=args.rate_delay,
        )
    )
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "source": NVD_BASE,
        "products": products,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    total = sum(len(records) for records in products.values())
    print(f"wrote {total} CVE records across {len(products)} products → {args.output}")  # noqa: T201
    return 0


async def _fetch_all(
    *,
    api_key: str | None,
    results_per_page: int,
    rate_delay: float,
) -> dict[str, list[dict[str, Any]]]:
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    out: dict[str, list[dict[str, Any]]] = {}
    request_index = 0
    async with httpx.AsyncClient(timeout=120.0, headers=headers) as client:
        for product_key, cpe_aliases in PRODUCTS.items():
            print(f"fetching {product_key} …", file=sys.stderr)  # noqa: T201
            collected: dict[str, dict[str, Any]] = {}
            for cpe in cpe_aliases:
                if request_index > 0:
                    await asyncio.sleep(rate_delay)
                request_index += 1
                records = await _fetch_product(client, cpe, results_per_page, rate_delay)
                for record in records:
                    cve_id = record["cve_id"]
                    if cve_id in collected:
                        existing = collected[cve_id]
                        existing_ranges = existing.get("ranges") or []
                        for new_range in record.get("ranges") or []:
                            if new_range not in existing_ranges:
                                existing_ranges.append(new_range)
                        existing["ranges"] = existing_ranges
                    else:
                        collected[cve_id] = record
            print(f"  {len(collected)} records", file=sys.stderr)  # noqa: T201
            out[product_key] = list(collected.values())
    return out


async def _fetch_product(
    client: httpx.AsyncClient,
    cpe: str,
    page_size: int,
    rate_delay: float,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    start_index = 0
    while True:
        body: dict[str, Any] | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                response = await client.get(
                    NVD_BASE,
                    params={
                        "virtualMatchString": cpe,
                        "resultsPerPage": page_size,
                        "startIndex": start_index,
                    },
                )
                response.raise_for_status()
                body = response.json()
                break
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                if attempt == _MAX_RETRIES - 1:
                    raise
                wait = rate_delay * (attempt + 1)
                print(f"  retry {attempt + 1} after {wait}s: {exc}", file=sys.stderr)  # noqa: T201
                await asyncio.sleep(wait)
        assert body is not None  # noqa: S101 -- loop above either sets or raises
        for vuln in body.get("vulnerabilities") or []:
            record = _transform(vuln, cpe)
            if record is not None:
                records.append(record)
        total = int(body.get("totalResults") or 0)
        start_index += page_size
        if start_index >= total:
            break
        await asyncio.sleep(rate_delay)
    return records


def _transform(vuln: dict[str, Any], cpe: str) -> dict[str, Any] | None:
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descriptions = cve.get("descriptions") or []
    summary = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value") if descriptions else "",
    )
    metrics = cve.get("metrics") or {}
    severity = "none"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((m for m in items if m.get("type") == "Primary"), items[0])
        cvss = primary.get("cvssData") or {}
        cvss_score = cvss.get("baseScore")
        cvss_vector = cvss.get("vectorString")
        severity = (primary.get("baseSeverity") or cvss.get("baseSeverity") or "none").lower()
        break
    references = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]
    ranges: list[dict[str, str | None]] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                criteria = match.get("criteria") or ""
                if not _cpe_matches(cpe, criteria):
                    continue
                introduced = match.get("versionStartIncluding") or match.get(
                    "versionStartExcluding"
                )
                fixed = match.get("versionEndExcluding")
                if introduced or fixed:
                    ranges.append({"introduced": introduced, "fixed": fixed, "exact": None})
                    continue
                exact = _extract_cpe_version(criteria)
                if exact:
                    ranges.append({"introduced": None, "fixed": None, "exact": exact})
    if not ranges:
        return None
    return {
        "cve_id": cve_id,
        "summary": summary,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published": cve.get("published"),
        "references": references,
        "ranges": ranges,
    }


def _extract_cpe_version(criteria: str) -> str | None:
    """Pull the version field out of a CPE 2.3 string, ignoring wildcards."""
    parts = criteria.split(":")
    if len(parts) < _CPE_MIN_FIELDS:
        return None
    version = parts[_CPE_VERSION_INDEX]
    if not version or version in {"*", "-"}:
        return None
    return version


def _cpe_matches(want: str, have: str) -> bool:
    want_parts = want.split(":")
    have_parts = have.split(":")
    common = min(len(want_parts), len(have_parts), 6)
    for i in range(common):
        wp, hp = want_parts[i], have_parts[i]
        if wp == "*" or hp == "*":
            continue
        if wp != hp:
            return False
    return True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
