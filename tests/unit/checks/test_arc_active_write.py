"""Unit tests for ARC-002 active mode (atomic addFeatures+deleteFeatures)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import respx
import structlog
from httpx import Response

from gisweep.core.context import Context
from gisweep.core.finding import Finding, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass

ROOT = "https://x.example/arcgis/rest/services"
LAYER = f"{ROOT}/Citizen/FeatureServer/0"


def _layer_payload(capabilities: str) -> dict[str, object]:
    return {
        "id": 0,
        "name": "People",
        "geometryType": "esriGeometryPoint",
        "capabilities": capabilities,
        "fields": [{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
    }


@pytest.fixture
async def ctx_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(active=True, i_own_this_target=True)
    http = HttpClient(options)
    yield Context(
        scan_id="scan-active-write",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check("ARC-002")
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_arc002_active_records_add_and_delete_in_audit(
    ctx_active: Context, tmp_path: Path
) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(200, json=_layer_payload("Query,Create,Update,Delete"))
    )
    respx.post(f"{LAYER}/addFeatures").mock(
        return_value=Response(200, json={"addResults": [{"objectId": 4242, "success": True}]})
    )
    respx.post(f"{LAYER}/deleteFeatures").mock(
        return_value=Response(200, json={"deleteResults": [{"objectId": 4242, "success": True}]})
    )

    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(target, ctx_active)
    assert len(findings) == 1
    assert "verified" in findings[0].description.lower()

    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    actions = [json.loads(line)["action"] for line in audit if line]
    assert actions == ["feature-add", "feature-delete"]
    statuses = [json.loads(line)["outcome"] for line in audit if line]
    assert statuses == ["success", "success"]


@respx.mock
async def test_arc002_active_alerts_when_delete_fails(ctx_active: Context, tmp_path: Path) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(200, json=_layer_payload("Query,Create,Update,Delete"))
    )
    respx.post(f"{LAYER}/addFeatures").mock(
        return_value=Response(200, json={"addResults": [{"objectId": 99, "success": True}]})
    )
    respx.post(f"{LAYER}/deleteFeatures").mock(return_value=Response(500))

    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(target, ctx_active)
    assert len(findings) == 1
    assert "could not be deleted" in findings[0].description.lower()
    assert "gisweep cleanup" in findings[0].description.lower()

    audit = [
        json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines() if line
    ]
    add_entry = next(e for e in audit if e["action"] == "feature-add")
    del_entry = next(e for e in audit if e["action"] == "feature-delete")
    assert add_entry["outcome"] == "success"
    assert del_entry["outcome"] == "failure"
    assert add_entry["details"]["object_id"] == 99


@respx.mock
async def test_arc002_active_passes_through_when_add_rejected(
    ctx_active: Context, tmp_path: Path
) -> None:
    respx.get(f"{LAYER}?f=json").mock(
        return_value=Response(200, json=_layer_payload("Query,Create,Update,Delete"))
    )
    respx.post(f"{LAYER}/addFeatures").mock(
        return_value=Response(
            200,
            json={
                "addResults": [
                    {"success": False, "error": {"code": 400, "message": "Required field missing"}}
                ]
            },
        )
    )

    target = TargetRef(url=LAYER, kind=TargetKind.ARCGIS_LAYER, layer_id=0)
    findings = await _collect(target, ctx_active)
    assert len(findings) == 1
    assert "active add+delete probe failed" in findings[0].description.lower()
