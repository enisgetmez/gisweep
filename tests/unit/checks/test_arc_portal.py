"""Unit tests for ARC-016 (Portal item ACL audit)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import respx
import structlog
from httpx import Response

from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass

PORTAL = "https://portal.example/portal"
SEARCH_URL = f"{PORTAL}/sharing/rest/search"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-arc016",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check("ARC-016")
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_arc016_flags_public_item_with_pii_in_metadata(ctx: Context) -> None:
    respx.get(SEARCH_URL).mock(
        return_value=Response(
            200,
            json={
                "results": [
                    {
                        "id": "abc123",
                        "title": "Citizen TCKN registry",
                        "snippet": "Personal numbers + email + telefon",
                        "description": "TCKN, email, phone",
                        "tags": ["citizen", "tckn"],
                        "type": "Feature Service",
                        "access": "public",
                        "url": "https://x.example/services/Citizen/FeatureServer",
                    },
                    {
                        "id": "def456",
                        "title": "City basemap tiles",
                        "snippet": "Streets and rivers",
                        "description": "",
                        "tags": ["basemap"],
                        "type": "Map Service",
                        "access": "public",
                        "url": "https://x.example/services/Basemap/MapServer",
                    },
                ]
            },
        )
    )
    target = TargetRef(url=f"{PORTAL}/sharing/rest", kind=TargetKind.ARCGIS_ROOT)
    findings = await _collect(target, ctx)
    assert len(findings) == 1
    assert findings[0].severity in {Severity.HIGH, Severity.CRITICAL}
    assert "Citizen TCKN registry" in findings[0].description


@respx.mock
async def test_arc016_silent_when_no_public_items_with_pii(ctx: Context) -> None:
    respx.get(SEARCH_URL).mock(
        return_value=Response(
            200,
            json={
                "results": [
                    {
                        "id": "x",
                        "title": "Public basemap",
                        "snippet": "OSM tiles",
                        "description": "",
                        "tags": ["basemap"],
                        "type": "Map Service",
                        "access": "public",
                    }
                ]
            },
        )
    )
    target = TargetRef(url=f"{PORTAL}/sharing/rest", kind=TargetKind.ARCGIS_ROOT)
    findings = await _collect(target, ctx)
    assert findings == []


@respx.mock
async def test_arc016_silent_when_url_is_not_a_portal(ctx: Context) -> None:
    target = TargetRef(url="https://x.example/arcgis/rest/services", kind=TargetKind.ARCGIS_ROOT)
    findings = await _collect(target, ctx)
    assert findings == []
