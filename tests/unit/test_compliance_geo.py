"""Unit tests for COMP-002 cross-border + COMP-004 precision overlay rules."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
import respx
from httpx import Response

from gisweep.compliance import apply_overlay, apply_overlay_async
from gisweep.compliance.geo import lookup_country, safe_country_codes
from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    pass


def _f(
    check_id: str,
    *,
    severity: Severity = Severity.HIGH,
    url: str = "https://x.example/arcgis/rest/services/Foo/FeatureServer/0",
    notes: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        severity=severity,
        target=TargetRef(url=url, kind=TargetKind.ARCGIS_LAYER),
        description="x",
        evidence=Evidence(notes=notes or []),
        remediation="x",
        kvkk_articles=["m12"],
        gdpr_articles=["art32"],
        discovered_at=datetime.now(tz=UTC),
        scan_id="scan-test",
    )


@pytest.fixture
async def http() -> AsyncIterator[HttpClient]:
    client = HttpClient(ScanOptions())
    yield client
    await client.aclose()


def test_safe_country_codes_loads_kvkk_and_gdpr() -> None:
    kvkk, gdpr = safe_country_codes()
    assert "TR" in kvkk
    assert "DE" in kvkk
    assert "GB" in gdpr
    assert "DE" in gdpr
    assert "RU" not in kvkk
    assert "CN" not in gdpr


@respx.mock
async def test_lookup_country_returns_iso2(http: HttpClient) -> None:
    respx.get("https://ipapi.co/example.com/country").mock(return_value=Response(200, text="US"))
    assert await lookup_country(http, "example.com") == "US"


@respx.mock
async def test_lookup_country_caches(http: HttpClient) -> None:
    route = respx.get("https://ipapi.co/example.com/country").mock(
        return_value=Response(200, text="DE")
    )
    cache: dict[str, str | None] = {}
    await lookup_country(http, "example.com", cache=cache)
    await lookup_country(http, "example.com", cache=cache)
    assert route.call_count == 1


@respx.mock
async def test_lookup_country_returns_none_on_error(http: HttpClient) -> None:
    respx.get("https://ipapi.co/example.com/country").mock(return_value=Response(500))
    assert await lookup_country(http, "example.com") is None


def test_comp004_fires_when_pii_layer_has_point_geometry() -> None:
    pii_with_point = _f("ARC-014", notes=["geometryType=esriGeometryPoint", "fields=TCKN"])
    pii_with_polygon = _f(
        "ARC-014",
        url="https://x.example/Polys/FeatureServer/0",
        notes=["geometryType=esriGeometryPolygon", "fields=TCKN"],
    )
    out = apply_overlay([pii_with_point, pii_with_polygon], scan_id="scan-test")
    comp = [f for f in out if f.check_id == "COMP-004"]
    assert len(comp) == 1
    assert comp[0].severity is Severity.HIGH


def test_comp004_silent_when_no_point_geometry() -> None:
    out = apply_overlay(
        [_f("ARC-014", notes=["geometryType=esriGeometryPolygon"])], scan_id="scan-test"
    )
    assert all(f.check_id != "COMP-004" for f in out)


@respx.mock
async def test_comp002_emits_for_non_safe_country(http: HttpClient) -> None:
    respx.get("https://ipapi.co/x.example/country").mock(return_value=Response(200, text="US"))
    findings = [_f("ARC-014", notes=["fields=TCKN"])]
    out = await apply_overlay_async(findings, scan_id="scan-test", http=http)
    comp = [f for f in out if f.check_id == "COMP-002"]
    assert len(comp) == 1
    assert comp[0].evidence.matched == "US"
    assert "m9" in comp[0].kvkk_articles


@respx.mock
async def test_comp002_silent_for_safe_country(http: HttpClient) -> None:
    respx.get("https://ipapi.co/x.example/country").mock(return_value=Response(200, text="DE"))
    findings = [_f("ARC-014")]
    out = await apply_overlay_async(findings, scan_id="scan-test", http=http)
    assert all(f.check_id != "COMP-002" for f in out)


@respx.mock
async def test_comp002_silent_when_geo_lookup_fails(http: HttpClient) -> None:
    respx.get("https://ipapi.co/x.example/country").mock(return_value=Response(500))
    findings = [_f("ARC-014")]
    out = await apply_overlay_async(findings, scan_id="scan-test", http=http)
    assert all(f.check_id != "COMP-002" for f in out)
