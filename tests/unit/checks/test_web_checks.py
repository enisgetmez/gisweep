"""Unit tests for the WEB-* check catalogue (mocked Playwright result)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import structlog

from gisweep.checks.web._helpers import CACHE_KEY
from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check
from gisweep.cve.db import (
    CveDatabase,
    CveRecord,
    CveSeverity,
    VersionRange,
    get_cve_database,
)
from gisweep.discovery.browser import (
    CapturedRequest,
    CapturedResponseBody,
    WebDiscoveryResult,
)
from gisweep.discovery.library_detect import DetectedLibrary

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

PAGE_URL = "https://demo.example/map"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-web",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


def _request(url: str, resource_type: str = "xhr") -> CapturedRequest:
    return CapturedRequest(
        url=url,
        method="GET",
        resource_type=resource_type,
        response_status=200,
        response_headers=(),
    )


def _discovery(
    *,
    requests: list[CapturedRequest] | None = None,
    libraries: list[DetectedLibrary] | None = None,
    bodies: list[CapturedResponseBody] | None = None,
    page_html: str = "<html></html>",
) -> WebDiscoveryResult:
    return WebDiscoveryResult(
        page_url=PAGE_URL,
        final_url=PAGE_URL,
        requests=requests or [],
        libraries=libraries or [],
        bodies=bodies or [],
        page_html=page_html,
    )


async def _collect(check_id: str, target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    instance = cls()
    return [f async for f in instance.run(target, ctx)]


async def test_web001_inventories_arcgis_and_mapbox_endpoints(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = _discovery(
        requests=[
            _request("https://x.gov/arcgis/rest/services/Foo/MapServer"),
            _request("https://api.mapbox.com/styles/v1/mapbox/streets-v11"),
            _request("https://demo.example/static/main.css"),
        ]
    )
    findings = await _collect("WEB-001", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert len(findings) == 1
    assert "arcgis_rest" in (findings[0].evidence.matched or "")
    assert "mapbox_api" in (findings[0].evidence.matched or "")


async def test_web001_silent_when_no_endpoints(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = _discovery(
        requests=[_request("https://demo.example/static/app.js", resource_type="script")]
    )
    findings = await _collect("WEB-001", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert findings == []


async def test_web002_finds_secret_in_inline_html(ctx: Context) -> None:
    page_html = """<!doctype html><html><body>
    <script>
        const apiKey = "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVWX";
    </script>
    </body></html>
    """
    ctx.cache[CACHE_KEY] = _discovery(page_html=page_html)
    findings = await _collect("WEB-002", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "google-maps-api-key" in findings[0].tags
    assert "AIzaSyA1234567890" not in (findings[0].evidence.matched or "")


async def test_web002_finds_secret_in_xhr_body(ctx: Context) -> None:
    body = '{"mapboxToken": "sk.eyJhYmMiOiJkZWYiLCJpYXQiOjE2MDAwMDAwMDB9.AAAAAAAAAAAAAAAAAAAAAAAA"}'
    bodies = [
        CapturedResponseBody(
            url="https://demo.example/api/config.json",
            resource_type="xhr",
            body=body,
        )
    ]
    ctx.cache[CACHE_KEY] = _discovery(bodies=bodies, page_html="<html></html>")
    findings = await _collect("WEB-002", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert any("mapbox-secret-token" in f.tags for f in findings)


async def test_web002_silent_on_clean_page(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = _discovery(page_html="<html><body>nothing</body></html>")
    findings = await _collect("WEB-002", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert findings == []


async def test_web007_matches_outdated_leaflet(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = _discovery(
        libraries=[DetectedLibrary("leaflet", "1.6.0", "global", "L.version=1.6.0")]
    )
    db = CveDatabase(
        schema_version=1,
        generated_at=None,
        source=None,
        products={
            "leafletjs:leaflet": (
                CveRecord(
                    cve_id="CVE-XXXX-LEAFLET",
                    summary="XSS in tooltip rendering.",
                    severity=CveSeverity.HIGH,
                    cvss_score=7.5,
                    cvss_vector=None,
                    published=None,
                    references=(),
                    ranges=(VersionRange(introduced=None, fixed="1.7.0"),),
                ),
            )
        },
    )
    get_cve_database.cache_clear()
    with patch("gisweep.checks.web.cves.get_cve_database", return_value=db):
        findings = await _collect("WEB-007", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "CVE-XXXX-LEAFLET" in findings[0].tags


async def test_web007_silent_when_no_libraries(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = _discovery(libraries=[])
    findings = await _collect("WEB-007", TargetRef(url=PAGE_URL, kind=TargetKind.WEB_PAGE), ctx)
    assert findings == []
