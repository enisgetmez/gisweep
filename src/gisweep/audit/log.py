"""Append-only JSONL audit log for active-mode operations.

Each entry has a stable schema (``gisweep.audit.v1``) so future tooling can
reliably parse the record. Tokens, passwords, and any credential-shaped
payload are passed through ``redact()`` before being written.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from gisweep.core.http import redact

SCHEMA = "gisweep.audit.v1"
_DEFAULT_RELATIVE_PATH = ".gisweep/audit.jsonl"
_ENV_OVERRIDE = "GISWEEP_AUDIT_LOG"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    scan_id: str
    check_id: str
    action: str  # short verb: "default-cred-probe", "feature-add+delete", "geometry-ssrf-probe"
    target_url: str
    outcome: AuditOutcome
    # value of --i-own-this-target / --authorized-by; redacted only when token-shaped
    operator: str
    details: dict[str, Any] = field(default_factory=dict)


def audit_log_path() -> Path:
    """Resolve where the JSONL log should be written."""
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        return Path(override).expanduser()
    return Path.home() / _DEFAULT_RELATIVE_PATH


def write_audit_entry(entry: AuditEntry, *, path: Path | None = None) -> Path:
    """Append one entry as JSONL. Returns the file path written to."""
    target = path if path is not None else audit_log_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "ts": datetime.now(tz=UTC).isoformat(),
        "scan_id": entry.scan_id,
        "check_id": entry.check_id,
        "action": entry.action,
        "target_url": entry.target_url,
        "outcome": entry.outcome.value,
        "operator": _redact_operator(entry.operator),
        "details": _redact_details(entry.details),
    }
    line = json.dumps(payload, ensure_ascii=False)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(line)
        fh.write("\n")
    return target


def _redact_operator(value: str) -> str:
    """Operator strings are usually ticket ids ('SEC-2026-04') and stay
    legible; only fingerprint when the value smells like a long token."""
    cleaned = value.strip()
    if len(cleaned) >= 32 and " " not in cleaned:  # noqa: PLR2004
        return redact(cleaned)
    return cleaned


_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"password", "secret", "token", "auth", "authorization", "cookie"}
)


def _redact_details(details: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in details.items():
        if any(marker in key.lower() for marker in _SENSITIVE_KEYS) and isinstance(value, str):
            out[key] = redact(value)
        else:
            out[key] = value
    return out
