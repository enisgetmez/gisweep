"""OGC scan runtime — probes WMS/WFS endpoints, populates the per-scan
capabilities cache, then runs the OGC check catalogue.

The CLI's ``ogc`` subcommand calls :func:`run` after parsing options into a
:class:`ScanRequest`. The implementation mirrors :mod:`gisweep.runtime.arcgis`
but with OGC discovery (GetCapabilities probing) instead of the REST walker.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep.checks.ogc._helpers import CACHE_KEY
from gisweep.compliance import apply_overlay_async
from gisweep.core.context import Context
from gisweep.core.finding import Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import AuthConfig, ScanOptions
from gisweep.core.runner import Runner
from gisweep.discovery.ogc_enum import OgcCapabilities, OgcEnumerator
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
    token: str | None = None
    active: bool = False
    i_own_this_target: bool = False
    outputs: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.INFO
    include: frozenset[str] = field(default_factory=frozenset)
    exclude: frozenset[str] = field(default_factory=frozenset)
    proxy: str | None = None
    rate_limit: float | None = None
    timeout: float = 30.0
    max_concurrency: int = 10
    verify_tls: bool = True


async def scan_only(
    request: ScanRequest,
    *,
    console: Console | None = None,
) -> tuple[list[Finding], ScanMeta] | None:
    """Probe the OGC endpoint, populate the capabilities cache, and run the
    OGC check catalogue. Returns ``(findings, meta)`` — or ``None`` when no
    GetCapabilities document was retrievable, which the orchestrator treats
    as exit code 2."""
    options = _build_options(request)
    log = structlog.get_logger("gisweep.runtime.ogc").bind(scan_id=request.scan_id)

    async with HttpClient(options) as http:
        if request.token is not None:
            options = dataclasses.replace(options, auth=AuthConfig(token=request.token))

        ctx = Context(
            scan_id=request.scan_id,
            options=options,
            http=http,
            logger=log,
            output_dir=request.output_dir,
        )
        capabilities, targets = await _discover(ctx, request.url)
        ctx.cache[CACHE_KEY] = capabilities

        if not capabilities:
            log.warning("ogc.no_capabilities", url=request.url)
            if console is not None:
                console.print(
                    "[yellow]⚠ No WMS / WFS GetCapabilities document was returned "
                    "by the probed endpoints. Check that the URL points at the "
                    "service root (e.g. [cyan]/geoserver/wms[/cyan] or "
                    "[cyan]/cgi-bin/mapserv[/cyan]) and that anonymous "
                    "GetCapabilities is allowed.[/yellow]"
                )
            return None

        services = sorted({cap.service for cap in capabilities})
        layer_total = sum(len(cap.layers) for cap in capabilities)
        software_versions = {
            f"{cap.fingerprint.software} {cap.fingerprint.version or 'unknown'}"
            for cap in capabilities
            if cap.fingerprint.software != "unknown"
        }
        if console is not None:
            software_str = (
                f" ([cyan]{', '.join(sorted(software_versions))}[/cyan])"
                if software_versions
                else ""
            )
            console.print(
                f"[dim]🔎 Discovered [bold]{len(capabilities)}[/bold] endpoint(s) "
                f"({', '.join(services)}) with [bold]{layer_total}[/bold] "
                f"layer(s)/feature-type(s){software_str}; running checks…[/dim]"
            )

        log.info(
            "ogc.scan_started",
            endpoints=len(capabilities),
            target_count=len(targets),
        )
        runner = Runner(ctx)
        with progress_callback(console) as on_progress:
            findings, meta = await runner.run(targets, on_progress=on_progress)
        findings = await apply_overlay_async(findings, scan_id=ctx.scan_id, http=http)

    return list(findings), meta


async def run(request: ScanRequest, *, console: Console | None = None) -> int:
    result = await scan_only(request, console=console)
    if result is None:
        return 2
    findings, meta = result
    _emit_outputs(findings, meta, request.outputs, console)
    return meta.exit_code


def _build_options(request: ScanRequest) -> ScanOptions:
    return ScanOptions(
        active=request.active,
        i_own_this_target=request.i_own_this_target,
        proxy=request.proxy,
        rate_limit=request.rate_limit,
        timeout=request.timeout,
        max_concurrency=request.max_concurrency,
        severity_threshold=request.severity_threshold,
        include=request.include,
        exclude=request.exclude,
        verify_tls=request.verify_tls,
        auth=AuthConfig(token=request.token) if request.token else None,
    )


async def _discover(ctx: Context, base_url: str) -> tuple[list[OgcCapabilities], list[TargetRef]]:
    """Walk the GetCapabilities probes and collapse "same server reachable
    via multiple aliased paths" into a single canonical target.

    Modern GeoServer routes ``/geoserver/wms``, ``/geoserver/wfs``,
    ``/geoserver/ows`` (and the bare ``/wms`` / ``/wfs`` / ``/ows`` paths
    when proxied) all into the same backend. Each one happily answers
    GetCapabilities, so without dedup every per-layer check fires once per
    alias and the report is N times the real finding count. We pick the first
    (host, fingerprint, service) we see and drop the rest.
    """
    enumerator = OgcEnumerator(ctx.http, base_url)
    capabilities: list[OgcCapabilities] = []
    seen_endpoint_service: set[tuple[str, str]] = set()
    seen_canonical: set[tuple[str, str, str | None, str]] = set()
    targets: list[TargetRef] = []
    async for cap in enumerator.probe():
        capabilities.append(cap)
        endpoint_service_key = (cap.endpoint_url, cap.service)
        if endpoint_service_key in seen_endpoint_service:
            continue
        seen_endpoint_service.add(endpoint_service_key)
        host = httpx.URL(cap.endpoint_url).host or ""
        canonical_key = (
            host,
            cap.fingerprint.software,
            cap.fingerprint.version,
            cap.service,
        )
        if canonical_key in seen_canonical:
            continue
        seen_canonical.add(canonical_key)
        targets.append(TargetRef(url=cap.endpoint_url, kind=TargetKind.OGC_SERVICE))
        # Per-feature-type targets so the data-exposure checks (OGC-006/007/008)
        # can run once per layer instead of per service. Only generated for
        # WFS — WMS layers don't expose attribute schemas via GetCapabilities.
        if cap.service == "WFS":
            for layer in cap.layers:
                if not layer.name:
                    continue
                targets.append(
                    TargetRef(
                        url=cap.endpoint_url,
                        kind=TargetKind.OGC_LAYER,
                        service_path=layer.name,
                    )
                )
    return capabilities, targets


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
