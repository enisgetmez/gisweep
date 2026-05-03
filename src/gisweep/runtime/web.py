"""Web crawler runtime — drives Playwright + WEB-* checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from gisweep.checks.web._helpers import CACHE_KEY
from gisweep.compliance import apply_overlay
from gisweep.core.context import Context
from gisweep.core.finding import Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.runner import Runner
from gisweep.discovery.browser import BrowserCrawler
from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.registry import build_writer, parse_output_arg

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
    discovery = await crawler.crawl(request.url)
    log.info(
        "web.crawl_complete",
        url=discovery.final_url,
        request_count=len(discovery.requests),
        body_count=len(discovery.bodies),
        library_count=len(discovery.libraries),
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
        findings, meta = await runner.run([target])
        findings = apply_overlay(findings, scan_id=ctx.scan_id)

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
