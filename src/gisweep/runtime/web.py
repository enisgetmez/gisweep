"""Web crawler runtime — drives Playwright + WEB-* checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from gisweep.checks.web._helpers import CACHE_KEY
from gisweep.compliance import apply_overlay_async
from gisweep.core.context import Context
from gisweep.core.finding import Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.runner import Runner
from gisweep.discovery.browser import BrowserCrawler
from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.registry import build_writer, parse_output_arg
from gisweep.runtime._progress import progress_callback

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from rich.console import Console

    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


@dataclass(frozen=True, slots=True)
class ScanRequest:
    url: str
    scan_id: str
    output_dir: Path
    outputs: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.INFO
    include: frozenset[str] = field(default_factory=frozenset)
    exclude: frozenset[str] = field(default_factory=frozenset)
    proxy: str | None = None
    timeout: float = 30.0
    verify_tls: bool = True
    headless: bool = True
    user_agent: str | None = None


async def run(request: ScanRequest, *, console: Console | None = None) -> int:
    log = structlog.get_logger("gisweep.runtime.web").bind(scan_id=request.scan_id)
    options = ScanOptions(
        severity_threshold=request.severity_threshold,
        include=request.include,
        exclude=request.exclude,
        proxy=request.proxy,
        timeout=request.timeout,
        verify_tls=request.verify_tls,
    )

    crawler = BrowserCrawler(headless=request.headless, user_agent=request.user_agent)
    log.info("web.crawl_started", url=request.url)
    if console is not None:
        console.print(f"[dim]🔎 Loading [cyan]{request.url}[/cyan] in headless Chromium…[/dim]")
    discovery = await crawler.crawl(request.url)
    log.info(
        "web.crawl_complete",
        url=discovery.final_url,
        request_count=len(discovery.requests),
        body_count=len(discovery.bodies),
        library_count=len(discovery.libraries),
    )
    if console is not None:
        if not discovery.requests and not discovery.page_html:
            console.print(
                "[yellow]⚠ The browser captured no responses from the page. The "
                "URL may be unreachable, blocked by CSP, or behind a login wall."
                "[/yellow]"
            )
        else:
            lib_summary = ", ".join(f"{lib.name}={lib.version}" for lib in discovery.libraries[:5])
            lib_str = f" [cyan]({lib_summary})[/cyan]" if lib_summary else ""
            console.print(
                f"[dim]🔎 Captured [bold]{len(discovery.requests)}[/bold] request(s), "
                f"[bold]{len(discovery.bodies)}[/bold] body(ies), "
                f"detected [bold]{len(discovery.libraries)}[/bold] GIS library(ies)"
                f"{lib_str}; running checks…[/dim]"
            )

    async with HttpClient(options) as http:
        ctx = Context(
            scan_id=request.scan_id,
            options=options,
            http=http,
            logger=log,
            output_dir=request.output_dir,
        )
        ctx.cache[CACHE_KEY] = discovery
        target = TargetRef(url=discovery.final_url, kind=TargetKind.WEB_PAGE)

        runner = Runner(ctx)
        with progress_callback(console) as on_progress:
            findings, meta = await runner.run([target], on_progress=on_progress)
        findings = await apply_overlay_async(findings, scan_id=ctx.scan_id, http=http)

    _emit_outputs(findings, meta, request.outputs, console)
    return meta.exit_code


def _emit_outputs(
    findings: Sequence[Finding],
    meta: ScanMeta,
    output_args: Sequence[str],
    console: Console | None,
) -> None:
    findings_list = list(findings)
    ConsoleWriter(console).write(findings_list, meta)
    for arg in output_args:
        spec = parse_output_arg(arg)
        writer = build_writer(spec)
        writer.write(findings_list, meta)
