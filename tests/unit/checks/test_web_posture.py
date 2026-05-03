"""Unit tests for WEB-003 / WEB-004 / WEB-005 / WEB-006."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import respx
import structlog
from httpx import Response

from gisweep.checks.web._helpers import CACHE_KEY
from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check
from gisweep.discovery.browser import (
    CapturedRequest,
    WebDiscoveryResult,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass

PAGE_URL_HTTPS = "https://demo.example/map"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-web-posture",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


def _request(url: str) -> CapturedRequest:
    return CapturedRequest(
        url=url,
        method="GET",
        resource_type="xhr",
        response_status=200,
        response_headers=(),
    )


async def _collect(check_id: str, target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_web003_flags_reflected_origin(ctx: Context) -> None:
    api = "https://api.x.example/arcgis/rest/services/Foo/MapServer"
    respx.options(api).mock(
        return_value=Response(
            204,
            headers={
                "Access-Control-Allow-Origin": "https://gisweep-cors-probe.example",
                "Access-Control-Allow-Methods": "GET",
            },
        )
    )
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        requests=[_request(api)],
    )
    findings = await _collect(
        "WEB-003", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@respx.mock
async def test_web003_flags_wildcard_with_credentials(ctx: Context) -> None:
    api = "https://api.x.example/arcgis/rest/services/Foo/MapServer"
    respx.options(api).mock(
        return_value=Response(
            204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        requests=[_request(api)],
    )
    findings = await _collect(
        "WEB-003", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert len(findings) == 1


@respx.mock
async def test_web003_silent_on_locked_down_cors(ctx: Context) -> None:
    api = "https://api.x.example/arcgis/rest/services/Foo/MapServer"
    respx.options(api).mock(
        return_value=Response(
            204,
            headers={"Access-Control-Allow-Origin": "https://prod.example"},
        )
    )
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        requests=[_request(api)],
    )
    findings = await _collect(
        "WEB-003", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert findings == []


async def test_web004_flags_http_asset_on_https_page(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        requests=[
            _request("http://tile.example/3/4/5.png"),
            _request("https://api.x.example/arcgis/rest/services/Foo/MapServer"),
        ],
    )
    findings = await _collect(
        "WEB-004", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "http://tile.example/3/4/5.png" in (findings[0].evidence.matched or "")


async def test_web004_silent_on_http_page(ctx: Context) -> None:
    page = "http://demo.example/map"
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=page,
        final_url=page,
        requests=[_request("http://tile.example/3/4/5.png")],
    )
    findings = await _collect("WEB-004", TargetRef(url=page, kind=TargetKind.WEB_PAGE), ctx)
    assert findings == []


async def test_web005_flags_third_party_script_without_sri(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        scripts=[
            {"src": "https://demo.example/static/app.js", "integrity": "", "crossorigin": ""},
            {"src": "https://cdn.example/leaflet.js", "integrity": "", "crossorigin": ""},
            {
                "src": "https://cdn.example/ok.js",
                "integrity": "sha384-abc123",
                "crossorigin": "anonymous",
            },
        ],
    )
    findings = await _collect(
        "WEB-005", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert len(findings) == 1
    assert "cdn.example/leaflet.js" in (findings[0].evidence.matched or "")
    assert "cdn.example/ok.js" not in (findings[0].evidence.matched or "")
    assert "demo.example/static/app.js" not in (findings[0].evidence.matched or "")


async def test_web006_flags_iframe_without_sandbox(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        iframes=[
            {"src": "https://embed.example/map", "sandbox": "", "referrerpolicy": ""},
            {
                "src": "https://safe.example/widget",
                "sandbox": "allow-scripts",
                "referrerpolicy": "",
            },
        ],
    )
    findings = await _collect(
        "WEB-006", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert len(findings) == 1
    assert "embed.example/map" in (findings[0].evidence.matched or "")
    assert "safe.example/widget" not in (findings[0].evidence.matched or "")


async def test_web006_silent_when_no_iframes(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = WebDiscoveryResult(
        page_url=PAGE_URL_HTTPS,
        final_url=PAGE_URL_HTTPS,
        iframes=[],
    )
    findings = await _collect(
        "WEB-006", TargetRef(url=PAGE_URL_HTTPS, kind=TargetKind.WEB_PAGE), ctx
    )
    assert findings == []
