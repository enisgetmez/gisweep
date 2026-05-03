"""Auto-detect dispatch for the ``gisweep scan`` subcommand.

Inspects the target URL (and a single probe response when needed) to decide
whether to dispatch to the ArcGIS REST runtime, the OGC runtime, or the
Playwright web crawler. The heuristic is intentionally conservative — when
the URL clearly says "/arcgis/rest/services" we trust it; otherwise we fetch
once and look at the response.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.runtime import arcgis as arcgis_runtime
from gisweep.runtime import ogc as ogc_runtime
from gisweep.runtime import web as web_runtime

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console


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
        return await web_runtime.run(
            web_runtime.ScanRequest(
                url=request.url,
                outputs=request.outputs,
                timeout=request.timeout,
                verify_tls=request.verify_tls,
                scan_id=request.scan_id,
                output_dir=request.output_dir,
            ),
            console=console,
        )
    log.warning("auto.unknown_target", url=request.url)
    return 2
