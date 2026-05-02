"""Markdown report writer — GitHub-friendly, KVKK/GDPR inline."""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING

from gisweep.core.finding import Severity
from gisweep.outputs._meta import compliance_matrix

if TYPE_CHECKING:
    from pathlib import Path

    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


_SEVERITY_BADGE: dict[Severity, str] = {
    Severity.INFO: "🛈 info",
    Severity.LOW: "🟦 low",
    Severity.MEDIUM: "🟨 medium",
    Severity.HIGH: "🟧 high",
    Severity.CRITICAL: "🟥 critical",
}


class MarkdownWriter:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: list[Finding], meta: ScanMeta) -> None:
        buf = StringIO()
        self._write_header(buf, findings, meta)
        self._write_summary(buf, findings, meta)
        self._write_compliance(buf, findings)
        self._write_findings(buf, findings)
        self._path.write_text(buf.getvalue(), encoding="utf-8")

    def _write_header(self, buf: StringIO, findings: list[Finding], meta: ScanMeta) -> None:
        duration = (meta.finished_at - meta.started_at).total_seconds()
        buf.write("# gisweep scan report\n\n")
        buf.write(f"- **scan_id:** `{meta.scan_id}`\n")
        buf.write(f"- **gisweep:** `{meta.gisweep_version}`\n")
        buf.write(
            f"- **duration:** `{duration:.2f}s` "
            f"(`{meta.started_at.isoformat()}` → `{meta.finished_at.isoformat()}`)\n"
        )
        buf.write(f"- **findings:** `{len(findings)}`\n")
        buf.write(f"- **exit_code:** `{meta.exit_code}`\n\n")
        if meta.targets:
            buf.write("**Targets:**\n\n")
            for url in meta.targets:
                buf.write(f"- `{url}`\n")
            buf.write("\n")

    def _write_summary(self, buf: StringIO, findings: list[Finding], meta: ScanMeta) -> None:
        buf.write("## Severity summary\n\n")
        if not findings:
            buf.write("No findings at or above the severity threshold.\n\n")
            return
        buf.write("| Severity | Count |\n|---|---:|\n")
        for sev in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ):
            count = meta.counts_by_severity.get(sev, 0)
            buf.write(f"| {_SEVERITY_BADGE[sev]} | {count} |\n")
        buf.write("\n")

    def _write_compliance(self, buf: StringIO, findings: list[Finding]) -> None:
        if not findings:
            return
        matrix = compliance_matrix(findings)
        if not matrix["kvkk"] and not matrix["gdpr"]:
            return
        buf.write("## Compliance impact\n\n")
        if matrix["kvkk"]:
            buf.write("### KVKK\n\n| Madde | Affected checks |\n|---|---|\n")
            for art, ids in matrix["kvkk"].items():
                buf.write(f"| {art} | {', '.join(ids)} |\n")
            buf.write("\n")
        if matrix["gdpr"]:
            buf.write("### GDPR\n\n| Article | Affected checks |\n|---|---|\n")
            for art, ids in matrix["gdpr"].items():
                buf.write(f"| {art} | {', '.join(ids)} |\n")
            buf.write("\n")

    def _write_findings(self, buf: StringIO, findings: list[Finding]) -> None:
        if not findings:
            return
        buf.write("## Findings\n\n")
        for f in findings:
            self._write_finding(buf, f)

    def _write_finding(self, buf: StringIO, f: Finding) -> None:
        buf.write(f"### {f.check_id} — {f.title} `{_SEVERITY_BADGE[f.severity]}`\n\n")
        buf.write(f"- **Target:** `{f.target.url}`")
        if f.target.service_path:
            buf.write(f" · service `{f.target.service_path}`")
        if f.target.layer_id is not None:
            buf.write(f" · layer `{f.target.layer_id}`")
        buf.write("\n")
        tags = _compliance_tags(f)
        if tags:
            buf.write(f"- **Compliance:** {' · '.join(tags)}\n")
        buf.write("\n")
        buf.write(f"{f.description.strip()}\n\n")
        if f.evidence.matched:
            buf.write(f"**Match:** `{f.evidence.matched}`\n\n")
        if f.evidence.notes:
            buf.write("**Evidence:**\n\n")
            for note in f.evidence.notes:
                buf.write(f"- {note}\n")
            buf.write("\n")
        if f.remediation.strip():
            buf.write(f"**Remediation:**\n\n{f.remediation.strip()}\n\n")
        if f.references:
            buf.write("**References:**\n\n")
            for ref in f.references:
                buf.write(f"- {ref}\n")
            buf.write("\n")
        buf.write("---\n\n")


def _compliance_tags(f: Finding) -> list[str]:
    tags: list[str] = []
    if f.cwe:
        tags.append(f"`{f.cwe}`")
    if f.cvss_vector:
        tags.append(f"CVSS `{f.cvss_vector}`")
    if f.kvkk_articles:
        tags.append(f"KVKK {', '.join(f.kvkk_articles)}")
    if f.gdpr_articles:
        tags.append(f"GDPR {', '.join(f.gdpr_articles)}")
    return tags
