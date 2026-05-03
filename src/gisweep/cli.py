"""gisweep CLI — Typer entry point with subcommands."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import gisweep.checks  # noqa: F401  -- side-effect: register checks
from gisweep import _version
from gisweep.core import registry
from gisweep.core.finding import Severity
from gisweep.runtime import arcgis as arcgis_runtime
from gisweep.runtime import auto as auto_runtime
from gisweep.runtime import ogc as ogc_runtime
from gisweep.runtime import secrets as secrets_runtime
from gisweep.runtime import web as web_runtime

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


def _parse_csv(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(part.strip() for part in value.split(",") if part.strip())


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL — kind auto-detected (ArcGIS / OGC / web)."),
    output: list[str] | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (extension implies format) or `format:path`. Repeatable.",
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification."),
) -> None:
    """Auto-detect the target kind and dispatch to the matching subcommand."""
    request = auto_runtime.DispatchRequest(
        url=url,
        outputs=tuple(output or ()),
        timeout=timeout,
        verify_tls=not no_verify_tls,
        scan_id=uuid.uuid4().hex,
        output_dir=Path.cwd(),
    )
    try:
        exit_code = asyncio.run(auto_runtime.run(request, console=console))
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/yellow]")
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


@app.command()
def arcgis(
    url: str = typer.Argument(..., help="ArcGIS REST root URL."),
    token: str | None = typer.Option(
        None, "--token", help="ArcGIS token; appended as ?token= and X-Esri-Authorization."
    ),
    username: str | None = typer.Option(None, "--username", help="ArcGIS username."),
    password: str | None = typer.Option(None, "--password", help="ArcGIS password."),
    portal_url: str | None = typer.Option(
        None,
        "--portal-url",
        help="Portal root used for /sharing/rest/generateToken (defaults to the target host).",
    ),
    referer: str | None = typer.Option(None, "--referer", help="Referer to bind tokens to."),
    active: bool = typer.Option(False, "--active", help="Enable intrusive active checks."),
    i_own_this_target: bool = typer.Option(
        False,
        "--i-own-this-target",
        help="Required with --active; affirms ownership / written authorization.",
    ),
    auth_bruteforce: bool = typer.Option(
        False, "--auth-bruteforce", help="Probe vendor default credentials (rate-limited)."
    ),
    ssrf_canary: str | None = typer.Option(
        None, "--ssrf-canary", help="Operator-supplied callback host for SSRF probes."
    ),
    output: list[str] | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (extension implies format) or `format:path`. Repeatable.",
    ),
    severity_threshold: Severity = typer.Option(
        Severity.INFO, "--severity-threshold", help="Drop findings below this severity."
    ),
    include: str | None = typer.Option(
        None, "--include", help="Comma-separated check ids to keep."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated check ids to drop."
    ),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL."),
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", help="Per-host requests per second cap."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
    max_concurrency: int = typer.Option(
        10, "--max-concurrency", help="Concurrent in-flight requests."
    ),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification."),
    max_depth: int = typer.Option(5, "--max-depth", help="Max folder recursion depth."),
) -> None:
    """Scan an ArcGIS REST endpoint."""
    if active and not i_own_this_target:
        console.print(
            "[red]--active requires --i-own-this-target (or --authorized-by). "
            "See SECURITY.md.[/red]"
        )
        raise typer.Exit(code=2)

    request = arcgis_runtime.ScanRequest(
        url=url,
        token=token,
        username=username,
        password=password,
        portal_url=portal_url,
        referer=referer,
        active=active,
        i_own_this_target=i_own_this_target,
        auth_bruteforce=auth_bruteforce,
        ssrf_canary=ssrf_canary,
        outputs=tuple(output or ()),
        severity_threshold=severity_threshold,
        include=_parse_csv(include),
        exclude=_parse_csv(exclude),
        proxy=proxy,
        rate_limit=rate_limit,
        timeout=timeout,
        max_concurrency=max_concurrency,
        verify_tls=not no_verify_tls,
        max_depth=max_depth,
        scan_id=uuid.uuid4().hex,
        output_dir=Path.cwd(),
    )
    try:
        exit_code = asyncio.run(arcgis_runtime.run(request, console=console))
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/yellow]")
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


@app.command()
def ogc(
    url: str = typer.Argument(
        ..., help="Base URL of the OGC server (WMS/WFS root or service path)."
    ),
    token: str | None = typer.Option(None, "--token", help="Bearer token, if any."),
    active: bool = typer.Option(False, "--active", help="Enable intrusive active checks."),
    i_own_this_target: bool = typer.Option(
        False,
        "--i-own-this-target",
        help="Required with --active; affirms ownership / written authorization.",
    ),
    output: list[str] | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (extension implies format) or `format:path`. Repeatable.",
    ),
    severity_threshold: Severity = typer.Option(
        Severity.INFO, "--severity-threshold", help="Drop findings below this severity."
    ),
    include: str | None = typer.Option(
        None, "--include", help="Comma-separated check ids to keep."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated check ids to drop."
    ),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL."),
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", help="Per-host requests per second cap."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
    max_concurrency: int = typer.Option(
        10, "--max-concurrency", help="Concurrent in-flight requests."
    ),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification."),
) -> None:
    """Scan an OGC web service (WMS / WFS over GeoServer, MapServer, QGIS Server)."""
    if active and not i_own_this_target:
        console.print(
            "[red]--active requires --i-own-this-target (or --authorized-by). "
            "See SECURITY.md.[/red]"
        )
        raise typer.Exit(code=2)

    request = ogc_runtime.ScanRequest(
        url=url,
        token=token,
        active=active,
        i_own_this_target=i_own_this_target,
        outputs=tuple(output or ()),
        severity_threshold=severity_threshold,
        include=_parse_csv(include),
        exclude=_parse_csv(exclude),
        proxy=proxy,
        rate_limit=rate_limit,
        timeout=timeout,
        max_concurrency=max_concurrency,
        verify_tls=not no_verify_tls,
        scan_id=uuid.uuid4().hex,
        output_dir=Path.cwd(),
    )
    try:
        exit_code = asyncio.run(ogc_runtime.run(request, console=console))
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/yellow]")
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


@app.command()
def web(
    url: str = typer.Argument(..., help="Web page URL — Playwright headless crawler."),
    output: list[str] | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (extension implies format) or `format:path`. Repeatable.",
    ),
    severity_threshold: Severity = typer.Option(
        Severity.INFO, "--severity-threshold", help="Drop findings below this severity."
    ),
    include: str | None = typer.Option(
        None, "--include", help="Comma-separated check ids to keep."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated check ids to drop."
    ),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL."),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification."),
    headed: bool = typer.Option(False, "--headed", help="Run Chromium with a visible window."),
    user_agent: str | None = typer.Option(
        None, "--user-agent", help="Override the default browser User-Agent."
    ),
) -> None:
    """Crawl a web page with Playwright and audit embedded GIS endpoints + secrets."""
    request = web_runtime.ScanRequest(
        url=url,
        outputs=tuple(output or ()),
        severity_threshold=severity_threshold,
        include=_parse_csv(include),
        exclude=_parse_csv(exclude),
        proxy=proxy,
        timeout=timeout,
        verify_tls=not no_verify_tls,
        headless=not headed,
        user_agent=user_agent,
        scan_id=uuid.uuid4().hex,
        output_dir=Path.cwd(),
    )
    try:
        exit_code = asyncio.run(web_runtime.run(request, console=console))
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/yellow]")
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


@app.command()
def secrets(
    url_or_path: str = typer.Argument(..., help="HTTPS URL or local file/directory path."),
    output: list[str] | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (extension implies format) or `format:path`. Repeatable.",
    ),
    severity_threshold: Severity = typer.Option(
        Severity.INFO, "--severity-threshold", help="Drop findings below this severity."
    ),
    include: str | None = typer.Option(
        None, "--include", help="Comma-separated check ids to keep."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated check ids to drop."
    ),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL."),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification."),
) -> None:
    """Scan a URL or local path for leaked API keys, tokens, and credentials."""
    request = secrets_runtime.ScanRequest(
        target=url_or_path,
        outputs=tuple(output or ()),
        severity_threshold=severity_threshold,
        include=_parse_csv(include),
        exclude=_parse_csv(exclude),
        proxy=proxy,
        timeout=timeout,
        verify_tls=not no_verify_tls,
        scan_id=uuid.uuid4().hex,
        output_dir=Path.cwd(),
    )
    try:
        exit_code = asyncio.run(secrets_runtime.run(request, console=console))
    except KeyboardInterrupt:
        console.print("[yellow]aborted[/yellow]")
        raise typer.Exit(code=2) from None
    raise typer.Exit(code=exit_code)


def main() -> None:  # pragma: no cover -- entry point shim
    app()


if __name__ == "__main__":
    main()
