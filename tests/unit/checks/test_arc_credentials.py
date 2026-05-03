"""Unit tests for ARC-004 (default credentials)."""

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

ROOT = "https://x.example/arcgis/rest/services"
TOKEN_URL = "https://x.example/arcgis/sharing/rest/generateToken"


@pytest.fixture
async def ctx_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(
        active=True,
        i_own_this_target=True,
        auth_bruteforce=True,
    )
    http = HttpClient(options)
    yield Context(
        scan_id="scan-cred",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


@pytest.fixture
async def ctx_passive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions()  # active=False, auth_bruteforce=False
    http = HttpClient(options)
    yield Context(
        scan_id="scan-cred-passive",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check("ARC-004")
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_arc004_silent_in_passive_mode(ctx_passive: Context) -> None:
    findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx_passive)
    assert findings == []


@respx.mock
async def test_arc004_emits_finding_when_default_cred_accepted(
    ctx_active: Context, tmp_path: Path
) -> None:
    # First two creds rejected, third accepted
    respx.post(TOKEN_URL).mock(
        side_effect=[
            Response(200, json={"error": {"code": 400, "message": "Invalid"}}),
            Response(200, json={"error": {"code": 400, "message": "Invalid"}}),
            Response(200, json={"token": "TOK-DEFAULT-CRED-12345", "expires": 1700000000000}),
        ]
    )
    findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx_active)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    # token must NOT appear in the finding evidence
    assert "TOK-DEFAULT-CRED-12345" not in (findings[0].evidence.matched or "")
    # Audit log must contain three attempts (2 failure, 1 success)
    audit_path = tmp_path / "audit.jsonl"
    assert audit_path.exists()
    lines = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    outcomes = [entry["outcome"] for entry in parsed]
    assert outcomes == ["failure", "failure", "success"]
    # password and token redacted in audit log too
    success_entry = parsed[-1]
    assert "TOK-DEFAULT-CRED" not in json.dumps(success_entry)


@respx.mock
async def test_arc004_silent_when_no_default_cred_accepted(ctx_active: Context) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={"error": {"code": 400, "message": "Invalid"}})
    )
    findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx_active)
    assert findings == []
