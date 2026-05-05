"""Auto-detect dispatch + pivot orchestrator for ``gisweep scan``.

Two responsibilities, kept in one module so the CLI surface stays small:

1. **Detect** the kind of target the operator pointed at (ArcGIS REST root /
   OGC service / web page / unknown). For the first three a single dedicated
   runtime answers the request and we hand off.
2. **Pivot** when the kind is *web*: after the Playwright crawler captures
   the network log, surface every ArcGIS REST and OGC endpoint the page
   actually used, and run the matching native scanner against each one. The
   pivot is restricted to endpoints that share the original URL's
   registrable domain so we never scan third-party tile / API services.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep.core.finding import Severity
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.runner import ScanMeta
from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.registry import build_writer, parse_output_arg
from gisweep.runtime import arcgis as arcgis_runtime
from gisweep.runtime import ogc as ogc_runtime
from gisweep.runtime import web as web_runtime
from gisweep.runtime._pivot import PivotTarget, extract_pivots

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from rich.console import Console

    from gisweep.core.finding import Finding


class TargetKindGuess(StrEnum):
    ARCGIS = "arcgis"
    OGC = "ogc"
    WEB = "web"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DispatchRequest:
    url: str
    scan_id: str
    output_dir: Path
    outputs: tuple[str, ...]
    timeout: float
    verify_tls: bool


_ARCGIS_PATH_RE = re.compile(r"/(?:arcgis|server)/rest/services", re.IGNORECASE)
_OGC_PATH_RE = re.compile(
    r"/(?:geoserver|wms|wfs|ows|cgi-bin/mapserv|mapserv)(?:[/?]|$)",
    re.IGNORECASE,
)


async def detect(url: str, *, http: HttpClient) -> TargetKindGuess:  # noqa: PLR0911 -- one return per detection signal is the clearest expression
    if _ARCGIS_PATH_RE.search(url):
        return TargetKindGuess.ARCGIS
    if _OGC_PATH_RE.search(url):
        return TargetKindGuess.OGC

    try:
        response = await http.get(url, follow_redirects=True)
    except (httpx.HTTPError, OSError):
        return TargetKindGuess.UNKNOWN
    body_excerpt = response.text[:8192].lower() if response.content else ""
    content_type = response.headers.get("content-type", "").lower()
    if "json" in content_type and (
        "currentversion" in body_excerpt or '"services"' in body_excerpt
    ):
        return TargetKindGuess.ARCGIS
    if "xml" in content_type and (
        "wms_capabilities" in body_excerpt or "wfs_capabilities" in body_excerpt
    ):
        return TargetKindGuess.OGC
    if "html" in content_type or body_excerpt.startswith("<!doctype html"):
        return TargetKindGuess.WEB
    return TargetKindGuess.UNKNOWN


async def run(request: DispatchRequest, *, console: Console | None = None) -> int:
    log = structlog.get_logger("gisweep.runtime.auto").bind(scan_id=request.scan_id)
    options = ScanOptions(timeout=request.timeout, verify_tls=request.verify_tls)
    async with HttpClient(options) as http:
        kind = await detect(request.url, http=http)
    log.info("auto.detected", url=request.url, kind=kind.value)
    if console is not None:
        if kind is TargetKindGuess.UNKNOWN:
            console.print(
                f"[yellow]⚠ Could not determine the kind of [cyan]{request.url}[/cyan]. "
                "Try the dedicated subcommand: [bold]arcgis[/bold], [bold]ogc[/bold], "
                "[bold]web[/bold], or [bold]secrets[/bold].[/yellow]"
            )
        else:
            console.print(
                f"[dim]🧭 Auto-detected target as [cyan]{kind.value}[/cyan]; "
                f"dispatching to [bold]gisweep {kind.value}[/bold]…[/dim]"
            )

    if kind is TargetKindGuess.ARCGIS:
        return await arcgis_runtime.run(
            arcgis_runtime.ScanRequest(
                url=request.url,
                outputs=request.outputs,
                timeout=request.timeout,
                verify_tls=request.verify_tls,
                scan_id=request.scan_id,
                output_dir=request.output_dir,
            ),
            console=console,
        )
    if kind is TargetKindGuess.OGC:
        return await ogc_runtime.run(
            ogc_runtime.ScanRequest(
                url=request.url,
                outputs=request.outputs,
                timeout=request.timeout,
                verify_tls=request.verify_tls,
                scan_id=request.scan_id,
                output_dir=request.output_dir,
            ),
            console=console,
        )
    if kind is TargetKindGuess.WEB:
        return await _run_web_with_pivot(request, console=console)
    log.warning("auto.unknown_target", url=request.url)
    return 2


async def _run_web_with_pivot(
    request: DispatchRequest,
    *,
    console: Console | None = None,
) -> int:
    """Crawl the page, run web checks, then pivot into native scanners for
    any same-domain ArcGIS / OGC endpoint the browser hit."""
    started_at = datetime.now(tz=UTC)
    web_request = web_runtime.ScanRequest(
        url=request.url,
        scan_id=request.scan_id,
        output_dir=request.output_dir,
        # outputs intentionally empty here — the orchestrator emits the
        # combined report once at the end so the operator sees one table.
        outputs=(),
        timeout=request.timeout,
        verify_tls=request.verify_tls,
    )
    web_findings, web_meta, discovery = await web_runtime.crawl_and_check(
        web_request, console=console
    )

    request_urls = [r.url for r in discovery.requests]
    pivots = extract_pivots(request_urls, base_url=request.url)
    if console is not None:
        if pivots:
            kinds_summary = ", ".join(
                f"{sum(1 for p in pivots if p.kind == kind)}x {kind}"
                for kind in sorted({p.kind for p in pivots})
            )
            console.print(
                f"[dim]🔗 Same-domain GIS endpoints in network log: "
                f"[bold]{kinds_summary}[/bold] — pivoting into the native "
                "scanner for each.[/dim]"
            )
            for p in pivots:
                console.print(
                    f"  [dim]→ [cyan]{p.kind}[/cyan] [bold]{p.url}[/bold] "
                    f"(seen as {_truncate(p.sample, 80)})[/dim]"
                )
        else:
            console.print(
                "[dim]🔗 No same-domain ArcGIS / OGC endpoints in the network "
                "log; nothing to pivot into.[/dim]"
            )

    findings_all: list[Finding] = list(web_findings)
    pivot_metas: list[ScanMeta] = []
    for pivot in pivots:
        pivot_findings, pivot_meta = await _scan_pivot(pivot, base_request=request, console=console)
        findings_all.extend(pivot_findings)
        pivot_metas.append(pivot_meta)

    finished_at = datetime.now(tz=UTC)
    combined_meta = _combine_meta(
        scan_id=request.scan_id,
        targets=(request.url,),
        started_at=started_at,
        finished_at=finished_at,
        web_meta=web_meta,
        pivot_metas=pivot_metas,
        findings=findings_all,
    )

    _emit_outputs(findings_all, combined_meta, request.outputs, console)
    return combined_meta.exit_code


async def _scan_pivot(
    pivot: PivotTarget,
    *,
    base_request: DispatchRequest,
    console: Console | None,
) -> tuple[list[Finding], ScanMeta]:
    """Dispatch a pivot target to the matching runtime. Each pivot gets its
    own scan_id (suffix) so the per-runtime audit log entries stay
    distinguishable while the operator still sees a single combined report."""
    pivot_scan_id = f"{base_request.scan_id}-{uuid.uuid4().hex[:8]}"
    if console is not None:
        console.print(f"\n[bold]▶ Pivoting into [cyan]{pivot.kind}[/cyan] scan: {pivot.url}[/bold]")

    if pivot.kind == "arcgis":
        result = await arcgis_runtime.scan_only(
            arcgis_runtime.ScanRequest(
                url=pivot.url,
                outputs=(),
                timeout=base_request.timeout,
                verify_tls=base_request.verify_tls,
                scan_id=pivot_scan_id,
                output_dir=base_request.output_dir,
            ),
            console=console,
        )
    elif pivot.kind == "ogc":
        result = await ogc_runtime.scan_only(
            ogc_runtime.ScanRequest(
                url=pivot.url,
                outputs=(),
                timeout=base_request.timeout,
                verify_tls=base_request.verify_tls,
                scan_id=pivot_scan_id,
                output_dir=base_request.output_dir,
            ),
            console=console,
        )
    else:
        result = None

    if result is None:
        # Discovery failed for the pivot — synthesize an empty meta so the
        # combined exit code is unaffected.
        empty = ScanMeta(
            scan_id=pivot_scan_id,
            started_at=datetime.now(tz=UTC),
            finished_at=datetime.now(tz=UTC),
            targets=(pivot.url,),
            gisweep_version="",
            exit_code=2,
            counts_by_severity=dict.fromkeys(Severity, 0),
        )
        return [], empty
    return result


def _combine_meta(
    *,
    scan_id: str,
    targets: tuple[str, ...],
    started_at: datetime,
    finished_at: datetime,
    web_meta: ScanMeta,
    pivot_metas: Sequence[ScanMeta],
    findings: Sequence[Finding],
) -> ScanMeta:
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    exit_code = max(
        (m.exit_code for m in (web_meta, *pivot_metas)),
        default=0,
    )
    return replace(
        web_meta,
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        targets=targets,
        exit_code=exit_code,
        counts_by_severity=counts,
    )


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


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"
