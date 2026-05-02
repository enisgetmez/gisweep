"""Unit tests for the console output writer."""

from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO

from rich.console import Console

from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef
from gisweep.core.runner import ScanMeta
from gisweep.outputs.console import ConsoleWriter


def _meta(counts: dict[Severity, int] | None = None) -> ScanMeta:
    return ScanMeta(
        scan_id="0123456789abcdef",
        started_at=datetime(2026, 5, 3, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 3, 12, 0, 1, tzinfo=UTC),
        targets=("https://x.example",),
        gisweep_version="0.1.0",
        exit_code=0,
        counts_by_severity=counts or dict.fromkeys(Severity, 0),
    )


def _finding(check_id: str = "ARC-002", severity: Severity = Severity.CRITICAL) -> Finding:
    return Finding(
        check_id=check_id,
        title="Anonymous write capability",
        severity=severity,
        target=TargetRef(url="https://x.example/arcgis/rest", kind=TargetKind.ARCGIS_ROOT),
        description="x",
        evidence=Evidence(),
        remediation="x",
        kvkk_articles=["m12"],
        gdpr_articles=["art32"],
        discovered_at=datetime(2026, 5, 3, tzinfo=UTC),
        scan_id="0123456789abcdef",
    )


def test_console_writer_renders_clean_panel() -> None:
    buf = StringIO()
    writer = ConsoleWriter(Console(file=buf, force_terminal=True, width=120))
    writer.write([], _meta())
    output = buf.getvalue()
    assert "clean" in output.lower() or "no findings" in output.lower()


def test_console_writer_renders_findings_table() -> None:
    buf = StringIO()
    writer = ConsoleWriter(Console(file=buf, force_terminal=False, width=120))
    counts = dict.fromkeys(Severity, 0)
    counts[Severity.CRITICAL] = 1
    writer.write([_finding()], _meta(counts))
    output = buf.getvalue()
    assert "ARC-002" in output
    assert "Anonymous write capability" in output
    assert "KVKK m12" in output
    assert "GDPR art32" in output
    assert "critical=1" in output
