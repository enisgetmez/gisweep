"""Unit tests for ARC-008 (Geometry SSRF) and ARC-009 (Print SSRF)."""

from __future__ import annotations

import json
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

GEOMETRY_SVC = "https://x.example/arcgis/rest/services/Utilities/Geometry/GeometryServer"
PRINT_SVC = "https://x.example/arcgis/rest/services/Utilities/PrintingTools/GPServer"
CANARY = "https://canary.example/abc123"


@pytest.fixture
async def ctx_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(
        active=True,
        i_own_this_target=True,
        ssrf_canary=CANARY,
    )
    http = HttpClient(options)
    yield Context(
        scan_id="scan-ssrf",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


@pytest.fixture
async def ctx_no_canary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(active=True, i_own_this_target=True)  # no ssrf_canary
    http = HttpClient(options)
    yield Context(
        scan_id="scan-ssrf-noc",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(check_id: str, target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_arc008_silent_when_no_canary(ctx_no_canary: Context) -> None:
    target = TargetRef(url=GEOMETRY_SVC, kind=TargetKind.ARCGIS_SERVICE)
    findings = await _collect("ARC-008", target, ctx_no_canary)
    assert findings == []


@respx.mock
async def test_arc008_emits_finding_when_probe_accepted(
    ctx_active: Context, tmp_path: Path
) -> None:
    respx.post(f"{GEOMETRY_SVC}/project").mock(return_value=Response(200, json={"geometries": []}))
    target = TargetRef(url=GEOMETRY_SVC, kind=TargetKind.ARCGIS_SERVICE)
    findings = await _collect("ARC-008", target, ctx_active)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert CANARY in (findings[0].evidence.matched or "")
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    parsed = json.loads(audit)
    assert parsed["action"] == "geometry-ssrf-probe"
    assert parsed["outcome"] == "success"
    assert parsed["details"]["canary"] == CANARY


@respx.mock
async def test_arc008_silent_when_probe_rejected(ctx_active: Context) -> None:
    respx.post(f"{GEOMETRY_SVC}/project").mock(return_value=Response(400))
    target = TargetRef(url=GEOMETRY_SVC, kind=TargetKind.ARCGIS_SERVICE)
    findings = await _collect("ARC-008", target, ctx_active)
    assert findings == []


@respx.mock
async def test_arc009_emits_finding_when_probe_accepted(
    ctx_active: Context, tmp_path: Path
) -> None:
    respx.post(f"{PRINT_SVC}/execute").mock(return_value=Response(200, json={"results": []}))
    target = TargetRef(url=PRINT_SVC, kind=TargetKind.ARCGIS_SERVICE)
    findings = await _collect("ARC-009", target, ctx_active)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    parsed = json.loads(audit)
    assert parsed["action"] == "print-ssrf-probe"
    assert parsed["details"]["canary"] == CANARY


@respx.mock
async def test_arc009_silent_for_non_print_service(ctx_active: Context) -> None:
    target = TargetRef(
        url="https://x.example/arcgis/rest/services/Foo/MapServer",
        kind=TargetKind.ARCGIS_SERVICE,
    )
    findings = await _collect("ARC-009", target, ctx_active)
    assert findings == []
