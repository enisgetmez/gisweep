"""gisweep CLI — Typer entry point with subcommands.

Phase 1 wires up ``checks list/info``, ``version``, and stub commands for the
scanner subcommands so that the CLI surface is fully discoverable end-to-end
even before any check is implemented.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# eager import so any registered checks populate the registry
import gisweep.checks  # noqa: F401
from gisweep import _version
from gisweep.core import registry

_HELP = "GIS vulnerability scanner — ArcGIS REST, embedded maps, secret detection, KVKK/GDPR-aware."

app = typer.Typer(
    name="gisweep",
    help=_HELP,
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)

checks_app = typer.Typer(help="Inspect the built-in check catalogue.", no_args_is_help=True)
app.add_typer(checks_app, name="checks")

console = Console()


@app.callback()
def _root() -> None:
    """gisweep — security and compliance scanner for GIS surfaces."""


@app.command()
def version() -> None:
    """Print the gisweep version."""
    console.print(f"gisweep {_version.__version__}")


@checks_app.command("list")
def checks_list(
    category: str | None = typer.Option(
        None, "--category", "-c", help="Filter by category (arcgis, web, secrets, compliance)."
    ),
) -> None:
    """List all registered checks."""
    rows = registry.all_meta()
    if category:
        rows = [m for m in rows if m.category == category]

    if not rows:
        console.print(
            Panel.fit(
                "No checks registered yet.\n"
                "Phase 2 lands the ArcGIS scanner; until then this list is empty.",
                title="gisweep checks",
                border_style="dim",
            )
        )
        return

    table = Table(title=f"gisweep checks ({len(rows)})", header_style="bold")
    table.add_column("ID", no_wrap=True, style="bold")
    table.add_column("Category", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    for m in sorted(rows, key=lambda x: x.id):
        table.add_row(m.id, m.category, m.severity.value, m.title)
    console.print(table)


@checks_app.command("info")
def checks_info(check_id: str = typer.Argument(..., help="Check id, e.g. ARC-002.")) -> None:
    """Show full metadata for a single check."""
    meta = registry.get_meta(check_id)
    if meta is None:
        console.print(f"[red]Unknown check id: {check_id!r}[/red]")
        raise typer.Exit(code=1)

    table = Table(title=f"{meta.id} — {meta.title}", show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold dim")
    table.add_column()
    table.add_row("Category", meta.category)
    table.add_row("Severity", meta.severity.value)
    if meta.cwe:
        table.add_row("CWE", meta.cwe)
    if meta.cvss_vector:
        table.add_row("CVSS", meta.cvss_vector)
    if meta.kvkk:
        table.add_row("KVKK", ", ".join(meta.kvkk))
    if meta.gdpr:
        table.add_row("GDPR", ", ".join(meta.gdpr))
    if meta.tags:
        table.add_row("Tags", ", ".join(meta.tags))
    table.add_row("Active mode", "yes" if meta.needs_active else "no")
    table.add_row("Verifiable in --active", "yes" if meta.can_verify_active else "no")
    if meta.references:
        table.add_row("References", "\n".join(meta.references))
    console.print(table)
    console.print(Panel(meta.description, border_style="dim", title="Description"))


def _not_implemented(name: str) -> None:
    console.print(f"[yellow]'{name}' is not yet implemented (Phase 2+).[/yellow]")
    raise typer.Exit(code=2)


@app.command()
def scan(url: str = typer.Argument(..., help="Target URL — kind auto-detected.")) -> None:
    """Scan a target with auto-detected kind dispatch."""
    _ = url
    _not_implemented("scan")


@app.command()
def arcgis(url: str = typer.Argument(..., help="ArcGIS REST root or service URL.")) -> None:
    """Scan an ArcGIS REST endpoint."""
    _ = url
    _not_implemented("arcgis")


@app.command()
def web(url: str = typer.Argument(..., help="Web page URL — Playwright crawler.")) -> None:
    """Scan a website for embedded maps and secret leakage."""
    _ = url
    _not_implemented("web")


@app.command()
def secrets(url_or_path: str = typer.Argument(..., help="URL or local path.")) -> None:
    """Scan for leaked secrets and API keys."""
    _ = url_or_path
    _not_implemented("secrets")


if __name__ == "__main__":
    app()
