"""Unit tests for ARC-001/002/003/013/014.

The conftest fixture wipes the registry; we re-import the arcgis checks
package inside each test to repopulate it for the duration of the test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import respx
import structlog
from httpx import Response

from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import AuthConfig, ScanOptions
from gisweep.core.registry import get_check

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

ROOT = "https://x.example/arcgis/rest/services"
LAYER = f"{ROOT}/Citizen/FeatureServer/0"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    context = Context(
        scan_id="scan-test",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    yield context
    await http.aclose()


def _layer_payload(
    *, capabilities: str, max_record_count: int | None, fields: list[dict[str, Any]]
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": 0,
        "name": "People",
        "geometryType": "esriGeometryPoint",
        "capabilities": capabilities,
        "fields": fields,
    }
    if max_record_count is not None:
        payload["maxRecordCount"] = max_record_count
    return payload


async def _collect(check_cls: type, target: TargetRef, ctx: Context) -> list[Finding]:
    instance = check_cls()
    return [f async for f in instance.run(target, ctx)]


@respx.mock
async def test_arc001_emits_finding_when_anonymous_root_returns_services(ctx: Context) -> None:
    respx.get(f"{ROOT}?f=json").mock(
        return_value=Response(
            200,
            json={
                "currentVersion": 10.91,
                "folders": [],
                "services": [{"name": "Citizen", "type": "FeatureServer"}],
            },
        )
    )
    cls = get_check("ARC-001")
    assert cls is not None
    findings = await _collect(cls, TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "Anonymous" in findings[0].title


@respx.mock
async def test_arc001_skipped_when_token_supplied(ctx: Context, tmp_path: Path) -> None:
    options = ScanOptions(auth=AuthConfig(token="t"))
    ctx2 = Context(
        scan_id="x",
        options=options,
        http=HttpClient(options),
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    try:
        cls = get_check("ARC-001")
        assert cls is not None
        findings = await _collect(cls, TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx2)
        assert findings == []
    finally:
        await ctx2.http.aclose()


@respx.mock
async def test_arc002_flags_anonymous_write_capability(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query,Create,Update,Delete",
                max_record_count=2000,
                fields=[{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
            ),
        )
    )
    cls = get_check("ARC-002")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert "Create" in (f.evidence.matched or "")


@respx.mock
async def test_arc002_no_finding_when_only_query_capability(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=1000,
                fields=[{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
            ),
        )
    )
    cls = get_check("ARC-002")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert findings == []


@respx.mock
async def test_arc003_admin_endpoint_reachable(ctx: Context) -> None:
    admin_url = "https://x.example/arcgis/admin"
    respx.get(admin_url).mock(
        return_value=Response(
            200,
            text="ArcGIS Server Administrator Directory",
            headers={"Content-Type": "text/html"},
        )
    )
    respx.get(admin_url + "/").mock(return_value=Response(404))
    respx.get("https://x.example/arcgis/portaladmin").mock(return_value=Response(404))
    respx.get("https://x.example/arcgis/portaladmin/").mock(return_value=Response(404))
    cls = get_check("ARC-003")
    assert cls is not None
    findings = await _collect(cls, TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


@respx.mock
async def test_arc003_no_finding_when_admin_returns_404(ctx: Context) -> None:
    respx.get(url__regex=r"https://x\.example/arcgis/(admin|portaladmin)/?").mock(
        return_value=Response(404)
    )
    cls = get_check("ARC-003")
    assert cls is not None
    findings = await _collect(cls, TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert findings == []


@respx.mock
async def test_arc013_flags_unbounded_layer(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=None,
                fields=[{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
            ),
        )
    )
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"count": 4242})
    )
    cls = get_check("ARC-013")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH


@respx.mock
async def test_arc013_demoted_to_medium_when_read_not_confirmed(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=None,
                fields=[{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
            ),
        )
    )
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(return_value=Response(401))
    cls = get_check("ARC-013")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


@respx.mock
async def test_arc013_silent_when_cap_below_threshold(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=500,
                fields=[{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
            ),
        )
    )
    cls = get_check("ARC-013")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert findings == []


@respx.mock
async def test_arc014_flags_pii_field_names(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=1000,
                fields=[
                    {"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"},
                    {"name": "TCKN", "alias": "TCKN", "type": "esriFieldTypeString"},
                    {"name": "Email", "alias": "E-Posta", "type": "esriFieldTypeString"},
                ],
            ),
        )
    )
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"count": 999})
    )
    cls = get_check("ARC-014")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert len(findings) == 1
    f = findings[0]
    assert "m12" in f.kvkk_articles
    assert "TCKN" in (f.evidence.matched or "")


@respx.mock
async def test_arc014_critical_for_sensitive_categories(ctx: Context) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(
            200,
            json=_layer_payload(
                capabilities="Query",
                max_record_count=1000,
                fields=[
                    {"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"},
                    {"name": "kan_grubu", "alias": "Kan Grubu", "type": "esriFieldTypeString"},
                ],
            ),
        )
    )
    respx.get(url__regex=rf"{LAYER}/query\?.*").mock(
        return_value=Response(200, json={"count": 999})
    )
    cls = get_check("ARC-014")
    assert cls is not None
    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(cls, target, ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "m6" in findings[0].kvkk_articles


@respx.mock
async def test_arc014_skipped_when_token_supplied(ctx: Context, tmp_path: Path) -> None:
    options = ScanOptions(auth=AuthConfig(token="t"))
    http = HttpClient(options)
    ctx2 = Context(
        scan_id="x",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    try:
        respx.get(f"{LAYER}?f=json").mock(
            return_value=Response(
                200,
                json=_layer_payload(
                    capabilities="Query",
                    max_record_count=1000,
                    fields=[{"name": "TCKN", "alias": "TCKN", "type": "esriFieldTypeString"}],
                ),
            )
        )
        cls = get_check("ARC-014")
        assert cls is not None
        target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
        findings = await _collect(cls, target, ctx2)
        assert findings == []
    finally:
        await http.aclose()
