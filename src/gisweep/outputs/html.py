"""Self-contained HTML report writer."""

from __future__ import annotations

from html import escape
from typing import TYPE_CHECKING

from gisweep.core.finding import Severity
from gisweep.outputs._meta import compliance_matrix

if TYPE_CHECKING:
    from pathlib import Path

    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.INFO: "#7da3a1",
    Severity.LOW: "#3b82f6",
    Severity.MEDIUM: "#eab308",
    Severity.HIGH: "#f97316",
    Severity.CRITICAL: "#dc2626",
}

_CSS = """
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; max-width: 1100px;
       margin: 2rem auto; padding: 0 1rem; color: #0f172a; background: #f8fafc; }
h1, h2, h3 { color: #0f172a; }
header { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; }
header .meta { color: #475569; font-size: 0.9rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
           gap: 0.75rem; margin: 1.5rem 0; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; }
.card .count { font-size: 2rem; font-weight: 700; }
.card .label { color: #64748b; text-transform: uppercase; font-size: 0.75rem;
               letter-spacing: 0.05em; }
.badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
         font-size: 0.75rem; font-weight: 600; color: #fff; }
.finding { background: #fff; border-radius: 8px; border: 1px solid #e2e8f0;
           padding: 1.25rem; margin-bottom: 1rem; }
.finding h3 { margin: 0 0 0.5rem 0; display: flex; gap: 0.5rem; align-items: center; }
.finding .target { color: #475569; font-size: 0.9rem; word-break: break-all; }
.finding .compliance { margin-top: 0.5rem; display: flex; flex-wrap: wrap; gap: 0.4rem; }
.finding .pill { background: #f1f5f9; color: #334155; padding: 0.15rem 0.55rem;
                 border-radius: 999px; font-size: 0.75rem; }
.finding pre { background: #f1f5f9; padding: 0.75rem; border-radius: 6px;
               overflow-x: auto; font-size: 0.85rem; }
.finding details { margin-top: 0.5rem; }
.finding details summary { cursor: pointer; color: #475569; font-size: 0.85rem; }
.matrix { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
.matrix th, .matrix td { text-align: left; padding: 0.5rem 0.75rem;
                          border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }
.matrix th { color: #475569; font-weight: 600; }
footer { color: #64748b; font-size: 0.8rem; text-align: center; margin: 3rem 0 1rem 0; }
.empty { background: #ecfdf5; border: 1px solid #a7f3d0; padding: 1rem;
         border-radius: 8px; color: #065f46; }
"""


class HtmlWriter:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: list[Finding], meta: ScanMeta) -> None:
        self._path.write_text(self._render(findings, meta), encoding="utf-8")

    def _render(self, findings: list[Finding], meta: ScanMeta) -> str:
        duration = (meta.finished_at - meta.started_at).total_seconds()
        parts: list[str] = [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            f"<title>gisweep report — {escape(meta.scan_id[:12])}</title>",
            f"<style>{_CSS}</style>",
            "</head><body>",
            "<header>",
            "<div><h1>gisweep report</h1>",
            f'<div class="meta">scan <code>{escape(meta.scan_id)}</code> · '
            f"gisweep <code>{escape(meta.gisweep_version)}</code> · "
            f"duration <code>{duration:.2f}s</code></div></div>",
            f'<div class="meta">{len(findings)} findings · exit code {meta.exit_code}</div>',
            "</header>",
        ]
        max_target_preview = 5
        if meta.targets:
            parts.append("<p class='meta'>Targets: ")
            parts.append(
                ", ".join(f"<code>{escape(t)}</code>" for t in meta.targets[:max_target_preview])
            )
            if len(meta.targets) > max_target_preview:
                parts.append(f" (+{len(meta.targets) - max_target_preview} more)")
            parts.append("</p>")

        parts.append('<section class="summary">')
        for sev in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ):
            count = meta.counts_by_severity.get(sev, 0)
            color = _SEVERITY_COLOR[sev]
            parts.append(
                f'<div class="card" style="border-top: 3px solid {color};">'
                f'<div class="count">{count}</div>'
                f'<div class="label">{escape(sev.value)}</div></div>'
            )
        parts.append("</section>")

        if not findings:
            parts.append('<div class="empty">No findings at or above the severity threshold.</div>')
        else:
            parts.append(self._compliance_section(findings))
            parts.append("<h2>Findings</h2>")
            parts.extend(self._render_finding(f) for f in findings)

        parts.append(
            "<footer>Generated by gisweep — "
            '<a href="https://github.com/enisgetmez/gisweep">github.com/enisgetmez/gisweep</a></footer>'
        )
        parts.append("</body></html>")
        return "\n".join(parts)

    def _compliance_section(self, findings: list[Finding]) -> str:
        matrix = compliance_matrix(findings)
        if not matrix["kvkk"] and not matrix["gdpr"]:
            return ""
        out: list[str] = ["<h2>Compliance impact</h2>"]
        if matrix["kvkk"]:
            out.append("<h3>KVKK</h3>")
            out.append('<table class="matrix"><thead>')
            out.append("<tr><th>Madde</th><th>Affected checks</th></tr></thead><tbody>")
            for art, ids in matrix["kvkk"].items():
                out.append(
                    f"<tr><td>{escape(art)}</td><td>{', '.join(escape(i) for i in ids)}</td></tr>"
                )
            out.append("</tbody></table>")
        if matrix["gdpr"]:
            out.append("<h3>GDPR</h3>")
            out.append('<table class="matrix"><thead>')
            out.append("<tr><th>Article</th><th>Affected checks</th></tr></thead><tbody>")
            for art, ids in matrix["gdpr"].items():
                out.append(
                    f"<tr><td>{escape(art)}</td><td>{', '.join(escape(i) for i in ids)}</td></tr>"
                )
            out.append("</tbody></table>")
        return "".join(out)

    def _render_finding(self, f: Finding) -> str:
        color = _SEVERITY_COLOR[f.severity]
        pills: list[str] = []
        if f.cwe:
            pills.append(f'<span class="pill">{escape(f.cwe)}</span>')
        pills.extend(f'<span class="pill">KVKK {escape(art)}</span>' for art in f.kvkk_articles)
        pills.extend(f'<span class="pill">GDPR {escape(art)}</span>' for art in f.gdpr_articles)
        if f.cvss_vector:
            pills.append(f'<span class="pill">CVSS {escape(f.cvss_vector)}</span>')
        evidence_html = ""
        if f.evidence.notes or f.evidence.matched:
            inner: list[str] = []
            if f.evidence.matched:
                inner.append(
                    f"<p><strong>Match:</strong> <code>{escape(f.evidence.matched)}</code></p>"
                )
            if f.evidence.notes:
                inner.append("<ul>")
                inner.extend(f"<li>{escape(n)}</li>" for n in f.evidence.notes)
                inner.append("</ul>")
            evidence_html = "<details><summary>Evidence</summary>" + "".join(inner) + "</details>"
        sev_label = escape(f.severity.value.upper())
        badge = f'<span class="badge" style="background:{color};">{sev_label}</span>'
        return (
            '<article class="finding">'
            f"<h3>{badge}<code>{escape(f.check_id)}</code> {escape(f.title)}</h3>"
            f'<div class="target">{escape(f.target.url)}</div>'
            f'<div class="compliance">{"".join(pills)}</div>'
            f"<p>{escape(f.description)}</p>"
            f"{evidence_html}"
            f"<p><strong>Remediation:</strong> {escape(f.remediation)}</p>"
            "</article>"
        )
