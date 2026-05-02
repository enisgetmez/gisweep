"""Rich console output writer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gisweep.core.finding import Severity

if TYPE_CHECKING:
    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "dim cyan",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bright_red",
    Severity.CRITICAL: "bold white on red",
}


class ConsoleWriter:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def write(self, findings: list[Finding], meta: ScanMeta) -> None:
        if not findings:
            self._console.print(
                Panel.fit(
                    Text("No findings at or above severity threshold.", style="green"),
                    title="gisweep — clean",
                    border_style="green",
                )
            )
            self._render_summary(meta)
            return

        table = Table(
            title=f"gisweep findings ({len(findings)})",
            show_lines=False,
            header_style="bold",
        )
        table.add_column("Severity", no_wrap=True)
        table.add_column("ID", no_wrap=True, style="bold")
        table.add_column("Title", overflow="fold")
        table.add_column("Target", overflow="fold", style="dim")
        table.add_column("Compliance", no_wrap=True)

        for f in findings:
            badge = Text(f.severity.value.upper(), style=_SEVERITY_STYLE[f.severity])
            compliance = ", ".join(
                [*[f"KVKK {a}" for a in f.kvkk_articles], *[f"GDPR {a}" for a in f.gdpr_articles]]
            )
            table.add_row(badge, f.check_id, f.title, f.target.url, compliance or "-")

        self._console.print(table)
        self._render_summary(meta)

    def _render_summary(self, meta: ScanMeta) -> None:
        duration = (meta.finished_at - meta.started_at).total_seconds()
        parts = [f"scan_id={meta.scan_id[:8]}", f"duration={duration:.2f}s"]
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = meta.counts_by_severity.get(sev, 0)
            if count:
                parts.append(f"{sev.value}={count}")
        self._console.print(f"[dim]gisweep — {' '.join(parts)}[/dim]")
