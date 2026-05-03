"""Unit tests for ARC-017 (read confirmation) and ARC-018 (inventory rollup)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import respx
import structlog
from httpx import Response

from gisweep.checks.arcgis._helpers import (
    LayerAccessProbe,
    cache_key,
    probe_layer_query,
)
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
LAYER = f"{ROOT}/Citizen/FeatureServer/0"


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
async def test_probe_layer_query_returns_count_on_success(ctx: Context) -> None:
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(return_value=Response(200, json={"count": 17}))
    probe = await probe_layer_query(ctx, LAYER)
    assert probe.confirmed_anonymous_read is True
    assert probe.count == 17
    assert probe.requires_auth is False


@respx.mock
async def test_probe_layer_query_marks_requires_auth(ctx: Context) -> None:
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(return_value=Response(401))
    probe = await probe_layer_query(ctx, LAYER)
    assert probe.confirmed_anonymous_read is False
    assert probe.requires_auth is True
    assert probe.status_code == 401


@respx.mock
async def test_probe_layer_query_handles_embedded_error(ctx: Context) -> None:
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"error": {"code": 403, "message": "Forbidden"}})
    )
    probe = await probe_layer_query(ctx, LAYER)
    assert probe.confirmed_anonymous_read is False
    assert probe.requires_auth is True


@respx.mock
async def test_probe_layer_query_caches(ctx: Context) -> None:
    route = respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"count": 5})
    )
    await probe_layer_query(ctx, LAYER)
    await probe_layer_query(ctx, LAYER)
    assert route.call_count == 1


@respx.mock
async def test_arc017_emits_finding_when_read_confirmed(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json={"name": "People", "fields": [], "capabilities": "Query"},
        )
    )
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"count": 1024})
    )
    findings = await _collect(
        "ARC-017", TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0), ctx
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "1024" in (findings[0].evidence.matched or "")


@respx.mock
async def test_arc017_silent_when_requires_auth(ctx: Context) -> None:
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(return_value=Response(403))
    findings = await _collect(
        "ARC-017", TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0), ctx
    )
    assert findings == []


async def test_arc018_inventory_rollup_summarises_cache(ctx: Context) -> None:
    layer_a = f"{ROOT}/Citizen/FeatureServer/0"
    layer_b = f"{ROOT}/Citizen/FeatureServer/1"
    layer_c = f"{ROOT}/Streets/FeatureServer/0"
    ctx.cache[cache_key("arcgis_layer_info", layer_a)] = {
        "name": "People",
        "fields": [{"name": "TCKN", "alias": "TCKN", "type": "esriFieldTypeString"}],
    }
    ctx.cache[cache_key("arcgis_layer_info", layer_b)] = {
        "name": "Audit",
        "fields": [{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
    }
    ctx.cache[cache_key("arcgis_layer_info", layer_c)] = {
        "name": "Roads",
        "fields": [{"name": "Ad", "alias": "Sokak Adi", "type": "esriFieldTypeString"}],
    }
    ctx.cache[cache_key("arcgis_layer_probe", layer_a)] = LayerAccessProbe(
        layer_url=layer_a,
        status_code=200,
        count=42,
        confirmed_anonymous_read=True,
        requires_auth=False,
    )
    ctx.cache[cache_key("arcgis_layer_probe", layer_b)] = LayerAccessProbe(
        layer_url=layer_b,
        status_code=401,
        count=None,
        confirmed_anonymous_read=False,
        requires_auth=True,
    )
    ctx.cache[cache_key("arcgis_layer_probe", layer_c)] = LayerAccessProbe(
        layer_url=layer_c,
        status_code=200,
        count=7,
        confirmed_anonymous_read=True,
        requires_auth=False,
    )

    findings = await _collect("ARC-018", TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert len(findings) == 1
    notes = "\n".join(findings[0].evidence.notes)
    assert "total_layers=3" in notes
    assert "anonymous_readable=2" in notes
    assert "requires_auth=1" in notes
    assert "pii_pattern_layers=2" in notes  # layer_a (TCKN) + layer_c (Ad/Sokak Adi)
    assert "pii_pattern_and_anonymous_read=2" in notes
