"""Integration test for ``gisweep cleanup`` against orphan audit-log entries."""

from __future__ import annotations

import json
from io import StringIO
from typing import TYPE_CHECKING

import pytest
import respx
from httpx import Response
from rich.console import Console

from gisweep.runtime.cleanup import CleanupRequest, _find_orphans, run

if TYPE_CHECKING:
    from pathlib import Path


def _audit_line(**fields: object) -> str:
    return json.dumps(fields)


def test_find_orphans_skips_entries_with_matching_delete(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    layer = "https://x.example/arcgis/rest/services/Foo/FeatureServer/0"
    log.write_text(
        "\n".join(
            [
                _audit_line(
                    schema="gisweep.audit.v1",
                    ts="2026-05-03T00:00:00+00:00",
                    scan_id="A",
                    check_id="ARC-002",
                    action="feature-add",
                    target_url=f"{layer}/addFeatures",
                    outcome="success",
                    operator="op",
                    details={"layer_url": layer, "object_id": 11, "test_id": "t11"},
                ),
                _audit_line(
                    schema="gisweep.audit.v1",
                    ts="2026-05-03T00:00:01+00:00",
                    scan_id="A",
                    check_id="ARC-002",
                    action="feature-delete",
                    target_url=f"{layer}/deleteFeatures",
                    outcome="success",
                    operator="op",
                    details={"layer_url": layer, "object_id": 11, "test_id": "t11"},
                ),
                _audit_line(
                    schema="gisweep.audit.v1",
                    ts="2026-05-03T00:00:02+00:00",
                    scan_id="B",
                    check_id="ARC-002",
                    action="feature-add",
                    target_url=f"{layer}/addFeatures",
                    outcome="success",
                    operator="op",
                    details={"layer_url": layer, "object_id": 22, "test_id": "t22"},
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    orphans = _find_orphans(log, scan_id=None)
    assert len(orphans) == 1
    assert orphans[0].object_id == 22
    assert orphans[0].scan_id == "B"


def test_find_orphans_filters_by_scan_id(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    layer = "https://x.example/arcgis/rest/services/Foo/FeatureServer/0"
    log.write_text(
        "\n".join(
            [
                _audit_line(
                    schema="gisweep.audit.v1",
                    ts="t0",
                    scan_id="A",
                    check_id="ARC-002",
                    action="feature-add",
                    target_url=f"{layer}/addFeatures",
                    outcome="success",
                    operator="op",
                    details={"layer_url": layer, "object_id": 11, "test_id": "t11"},
                ),
                _audit_line(
                    schema="gisweep.audit.v1",
                    ts="t1",
                    scan_id="B",
                    check_id="ARC-002",
                    action="feature-add",
                    target_url=f"{layer}/addFeatures",
                    outcome="success",
                    operator="op",
                    details={"layer_url": layer, "object_id": 22, "test_id": "t22"},
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    assert [o.object_id for o in _find_orphans(log, scan_id="A")] == [11]
    assert [o.object_id for o in _find_orphans(log, scan_id="B")] == [22]


@pytest.mark.asyncio
@respx.mock
async def test_cleanup_deletes_orphan_and_appends_audit_entry(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    layer = "https://x.example/arcgis/rest/services/Foo/FeatureServer/0"
    log.write_text(
        _audit_line(
            schema="gisweep.audit.v1",
            ts="t0",
            scan_id="A",
            check_id="ARC-002",
            action="feature-add",
            target_url=f"{layer}/addFeatures",
            outcome="success",
            operator="op",
            details={"layer_url": layer, "object_id": 7, "test_id": "t7"},
        )
        + "\n",
        encoding="utf-8",
    )
    respx.post(f"{layer}/deleteFeatures").mock(
        return_value=Response(200, json={"deleteResults": [{"objectId": 7, "success": True}]})
    )

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    code = await run(CleanupRequest(audit_log=log), console=console)
    assert code == 0

    parsed = [json.loads(line) for line in log.read_text().splitlines() if line]
    cleanup_entries = [e for e in parsed if e["action"] == "feature-cleanup"]
    assert len(cleanup_entries) == 1
    assert cleanup_entries[0]["outcome"] == "success"


@pytest.mark.asyncio
async def test_cleanup_dry_run_does_not_call_server(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    layer = "https://x.example/arcgis/rest/services/Foo/FeatureServer/0"
    log.write_text(
        _audit_line(
            schema="gisweep.audit.v1",
            ts="t0",
            scan_id="A",
            check_id="ARC-002",
            action="feature-add",
            target_url=f"{layer}/addFeatures",
            outcome="success",
            operator="op",
            details={"layer_url": layer, "object_id": 7, "test_id": "t7"},
        )
        + "\n",
        encoding="utf-8",
    )
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    code = await run(CleanupRequest(audit_log=log, dry_run=True), console=console)
    assert code == 0
    assert "Dry run" in buf.getvalue()
