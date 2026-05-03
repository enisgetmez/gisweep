"""Runtime for the ``gisweep cleanup`` subcommand.

Walks the audit log, finds ``feature-add`` entries that do not have a
matching successful ``feature-delete``, and tries to delete the orphan(s)
through ``deleteFeatures``. Always non-destructive in the sense that it
only deletes features previously created by gisweep itself (identified by
the ``test_id`` attribute and the ``layer_url``/``object_id`` recorded in
the audit log).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep.audit import AuditEntry, AuditOutcome, audit_log_path, write_audit_entry
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console


_HTTP_OK = 200


@dataclass(frozen=True, slots=True)
class CleanupRequest:
    scan_id: str | None = None
    audit_log: Path | None = None
    dry_run: bool = False
    timeout: float = 30.0
    verify_tls: bool = True


@dataclass(slots=True)
class _Orphan:
    scan_id: str
    layer_url: str
    object_id: int
    test_id: str
    add_ts: str
    deleted: bool = False
    delete_attempts: list[str] = field(default_factory=list)


async def run(  # noqa: PLR0912 -- one branch per outcome line, splitting hurts readability
    request: CleanupRequest, *, console: Console | None = None
) -> int:
    log_path = request.audit_log or audit_log_path()
    if not log_path.exists():
        if console is not None:
            console.print(
                f"[dim]No audit log found at [cyan]{log_path}[/cyan]; nothing to clean.[/dim]"
            )
        return 0

    orphans = _find_orphans(log_path, request.scan_id)
    if not orphans:
        if console is not None:
            console.print(f"[dim]✓ No orphaned test features in [cyan]{log_path}[/cyan].[/dim]")
        return 0

    if console is not None:
        console.print(
            f"[yellow]Found {len(orphans)} orphan test feature(s) in {log_path}:[/yellow]"
        )
        for orphan in orphans:
            console.print(
                f"  • scan={orphan.scan_id[:8]} layer={orphan.layer_url} "
                f"object_id={orphan.object_id} test_id={orphan.test_id}"
            )

    if request.dry_run:
        if console is not None:
            console.print("[dim]Dry run: not attempting deletion.[/dim]")
        return 0

    options = ScanOptions(timeout=request.timeout, verify_tls=request.verify_tls)
    log = structlog.get_logger("gisweep.runtime.cleanup")
    failed = 0
    async with HttpClient(options) as http:
        for orphan in orphans:
            if console is not None:
                console.print(
                    f"[dim]Deleting object_id={orphan.object_id} on {orphan.layer_url}…[/dim]"
                )
            success = await _delete_orphan(http, orphan, log)
            write_audit_entry(
                AuditEntry(
                    scan_id=orphan.scan_id,
                    check_id="ARC-002",
                    action="feature-cleanup",
                    target_url=f"{orphan.layer_url.rstrip('/')}/deleteFeatures",
                    outcome=AuditOutcome.SUCCESS if success else AuditOutcome.FAILURE,
                    operator="gisweep-cleanup",
                    details={
                        "layer_url": orphan.layer_url,
                        "object_id": orphan.object_id,
                        "test_id": orphan.test_id,
                        "ts": datetime.now(tz=UTC).isoformat(),
                    },
                ),
                path=log_path,
            )
            if not success:
                failed += 1

    if console is not None:
        if failed:
            console.print(
                f"[red]{failed} of {len(orphans)} cleanup(s) failed. "
                "Re-run after the network/auth issue is resolved, or delete the "
                "feature manually using the recorded test_id.[/red]"
            )
        else:
            console.print(f"[green]✓ All {len(orphans)} orphan test feature(s) deleted.[/green]")

    return 0 if failed == 0 else 2


def _find_orphans(log_path: Path, scan_id: str | None) -> list[_Orphan]:
    """Walk the JSONL log; return orphan records (add without matching delete)."""
    adds: dict[tuple[str, int], _Orphan] = {}
    deletes: set[tuple[str, int]] = set()
    cleanups: set[tuple[str, int]] = set()
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()  # noqa: PLW2901
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if scan_id is not None and entry.get("scan_id") != scan_id:
            continue
        action = entry.get("action")
        details = entry.get("details") or {}
        layer_url = str(details.get("layer_url") or "")
        object_id_raw = details.get("object_id")
        if not isinstance(object_id_raw, int):
            continue
        key = (layer_url, object_id_raw)
        if action == "feature-add" and entry.get("outcome") == "success":
            adds[key] = _Orphan(
                scan_id=str(entry.get("scan_id") or ""),
                layer_url=layer_url,
                object_id=object_id_raw,
                test_id=str(details.get("test_id") or ""),
                add_ts=str(entry.get("ts") or ""),
            )
        elif action in {"feature-delete", "feature-cleanup"} and entry.get("outcome") == "success":
            (deletes if action == "feature-delete" else cleanups).add(key)
    return [orphan for key, orphan in adds.items() if key not in deletes and key not in cleanups]


async def _delete_orphan(
    http: HttpClient,
    orphan: _Orphan,
    log: structlog.stdlib.BoundLogger,
) -> bool:
    delete_url = f"{orphan.layer_url.rstrip('/')}/deleteFeatures"
    payload = {"f": "json", "objectIds": str(orphan.object_id)}
    try:
        response = await http.post(delete_url, data=payload)
    except (httpx.HTTPError, OSError) as exc:
        orphan.delete_attempts.append(f"http_error:{exc}")
        log.warning("cleanup.delete_failed", url=delete_url, error=str(exc))
        return False
    if response.status_code != _HTTP_OK:
        orphan.delete_attempts.append(f"status:{response.status_code}")
        return False
    try:
        body = response.json()
    except ValueError:
        orphan.delete_attempts.append("non_json_response")
        return False
    results = body.get("deleteResults") if isinstance(body, dict) else None
    if not isinstance(results, list) or not results:
        orphan.delete_attempts.append("no_delete_results")
        return False
    first = results[0]
    if isinstance(first, dict) and first.get("success") is True:
        orphan.deleted = True
        return True
    orphan.delete_attempts.append(str(first))
    return False
