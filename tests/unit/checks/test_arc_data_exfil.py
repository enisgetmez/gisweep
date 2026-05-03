"""Unit tests for ARC-011 (Sync/Extract) and ARC-012 (ExportTiles)."""

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

ROOT = "https://x.example/arcgis/rest/services"
FEATURESERVER = f"{ROOT}/Citizen/FeatureServer"
MAPSERVER = f"{ROOT}/Streets/MapServer"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-test",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(check_id: str, target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    instance = cls()
    return [f async for f in instance.run(target, ctx)]


@respx.mock
async def test_arc011_flags_sync_capability(ctx: Context) -> None:
    respx.get(f"{FEATURESERVER}?f=json").mock(
        return_value=Response(
            200,
            json={"capabilities": "Query,Create,Update,Delete,Sync"},
        )
    )
    findings = await _collect(
        "ARC-011",
        TargetRef(url=FEATURESERVER, kind=TargetKind.ARCGIS_SERVICE),
        ctx,
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


@respx.mock
async def test_arc011_silent_on_query_only(ctx: Context) -> None:
    respx.get(f"{FEATURESERVER}?f=json").mock(
        return_value=Response(200, json={"capabilities": "Query"})
    )
    findings = await _collect(
        "ARC-011",
        TargetRef(url=FEATURESERVER, kind=TargetKind.ARCGIS_SERVICE),
        ctx,
    )
    assert findings == []


@respx.mock
async def test_arc012_flags_export_tiles(ctx: Context) -> None:
    respx.get(f"{MAPSERVER}?f=json").mock(
        return_value=Response(
            200,
            json={"capabilities": "Map,Query,Data,ExportTiles"},
        )
    )
    findings = await _collect(
        "ARC-012",
        TargetRef(url=MAPSERVER, kind=TargetKind.ARCGIS_SERVICE),
        ctx,
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


@respx.mock
async def test_arc012_silent_when_export_disabled(ctx: Context) -> None:
    respx.get(f"{MAPSERVER}?f=json").mock(
        return_value=Response(200, json={"capabilities": "Map,Query"})
    )
    findings = await _collect(
        "ARC-012",
        TargetRef(url=MAPSERVER, kind=TargetKind.ARCGIS_SERVICE),
        ctx,
    )
    assert findings == []
