"""Unit tests for the audit log."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from gisweep.audit import AuditEntry, AuditOutcome, write_audit_entry

if TYPE_CHECKING:
    from pathlib import Path


def test_audit_log_writes_jsonl_line(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    write_audit_entry(
        AuditEntry(
            scan_id="scan-x",
            check_id="ARC-004",
            action="default-cred-probe",
            target_url="https://x.example/portal/sharing/rest/generateToken",
            outcome=AuditOutcome.FAILURE,
            operator="SEC-2026-04",
            details={
                "username": "esri",
                "password": "esri",
                "issued_token": None,
            },
        ),
        path=log,
    )
    line = log.read_text(encoding="utf-8").strip()
    payload = json.loads(line)
    assert payload["schema"] == "gisweep.audit.v1"
    assert payload["check_id"] == "ARC-004"
    assert payload["operator"] == "SEC-2026-04"
    assert payload["details"]["username"] == "esri"
    # password keyed entry is redacted
    assert (
        payload["details"]["password"].startswith("***") or payload["details"]["password"] == "***"
    )


def test_audit_log_redacts_long_token_operator(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    long_token = "T0K3N-" + "a" * 64
    write_audit_entry(
        AuditEntry(
            scan_id="x",
            check_id="ARC-004",
            action="default-cred-probe",
            target_url="https://x.example/portal/sharing/rest/generateToken",
            outcome=AuditOutcome.SUCCESS,
            operator=long_token,
            details={},
        ),
        path=log,
    )
    payload = json.loads(log.read_text(encoding="utf-8").strip())
    assert long_token not in payload["operator"]
    assert "***" in payload["operator"]


def test_audit_log_appends(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    for i in range(3):
        write_audit_entry(
            AuditEntry(
                scan_id="x",
                check_id="ARC-004",
                action=f"probe-{i}",
                target_url="https://x.example",
                outcome=AuditOutcome.SKIPPED,
                operator="op",
                details={},
            ),
            path=log,
        )
    lines = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3
