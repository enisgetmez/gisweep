"""ArcGIS scan runtime — discovery + runner orchestration.

The CLI's ``arcgis`` subcommand parses options into a :class:`ScanRequest` and
hands off to :func:`run`, which:

1. Builds a shared HttpClient (or accepts an injected one for tests).
2. If credentials are supplied, exchanges them for a token via
   :func:`gisweep.auth.arcgis_token.generate_token`.
3. Walks the REST root with :class:`ArcGISEnumerator` to assemble a target list
   (root + each service + each layer/table).
4. Hands the target list to :class:`Runner` to execute the registered checks.
5. Streams findings to console plus any file writers parsed from ``-o`` flags.

The function is async and returns the exit code so the CLI does
``raise typer.Exit(asyncio.run(run(...)))``.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep.auth.arcgis_token import generate_token
from gisweep.compliance import apply_overlay_async
from gisweep.core.context import Context
from gisweep.core.finding import Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import AuthConfig, ScanOptions
from gisweep.core.runner import Runner
from gisweep.discovery.arcgis_enum import ArcGISEnumerator, ArcGISServiceRef
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
    username: str | None = None
    password: str | None = None
    portal_url: str | None = None
    referer: str | None = None
    active: bool = False
    i_own_this_target: bool = False
    auth_bruteforce: bool = False
    ssrf_canary: str | None = None
    outputs: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.INFO
    include: frozenset[str] = field(default_factory=frozenset)
    exclude: frozenset[str] = field(default_factory=frozenset)
    proxy: str | None = None
    rate_limit: float | None = None
    timeout: float = 30.0
    max_concurrency: int = 10
    verify_tls: bool = True
    max_depth: int = 5


async def scan_only(
    request: ScanRequest,
    *,
    console: Console | None = None,
) -> tuple[list[Finding], ScanMeta] | None:
    """Run discovery + checks and return ``(findings, meta)``.

    Returns ``None`` when discovery yields zero targets — the orchestrator
    treats that as a soft failure (exit code 2) without emitting an empty
    report. ``run`` wraps this and writes outputs.
    """
    options = _build_options(request)
    log = structlog.get_logger("gisweep.runtime.arcgis").bind(scan_id=request.scan_id)

    async with HttpClient(options) as http:
        token = request.token
        if token is None and request.username and request.password:
            portal = request.portal_url or _derive_portal_url(request.url)
            log.info("arcgis.token.generate", portal_url=portal, username=request.username)
            tok = await generate_token(
                http,
                portal_url=portal,
                username=request.username,
                password=request.password,
                referer=request.referer or _DEFAULT_REFERER,
            )
            token = tok.token

        if token is not None:
            options = dataclasses.replace(
                options,
                auth=AuthConfig(
                    token=token,
                    username=request.username,
                    password=None,
                    portal_url=request.portal_url,
                    referer=request.referer,
                ),
            )

        ctx = Context(
            scan_id=request.scan_id,
            options=options,
            http=http,
            logger=log,
            output_dir=request.output_dir,
        )
        if token is not None:
            ctx.cache["arcgis_token"] = token

        targets = await _build_targets(ctx, request, console=console)
        if not targets:
            log.warning("arcgis.no_targets", url=request.url)
            return None

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


_DEFAULT_REFERER = "https://www.arcgis.com"


def _build_options(request: ScanRequest) -> ScanOptions:
    auth: AuthConfig | None = None
    if any((request.token, request.username, request.password)):
        auth = AuthConfig(
            token=request.token,
            username=request.username,
            password=request.password,
            portal_url=request.portal_url,
            referer=request.referer,
        )
    return ScanOptions(
        active=request.active,
        i_own_this_target=request.i_own_this_target,
        auth_bruteforce=request.auth_bruteforce,
        ssrf_canary=request.ssrf_canary,
        proxy=request.proxy,
        rate_limit=request.rate_limit,
        timeout=request.timeout,
        max_concurrency=request.max_concurrency,
        severity_threshold=request.severity_threshold,
        include=request.include,
        exclude=request.exclude,
        auth=auth,
        verify_tls=request.verify_tls,
    )


_REST_ROOT_NEEDS_SERVICES = re.compile(r"/(?:arcgis|server)/rest/?$", re.IGNORECASE)


def normalize_rest_root(url: str) -> str:
    """Append ``/services`` when the user pointed at ``/arcgis/rest`` or
    ``/server/rest`` instead of the canonical ``/arcgis/rest/services``.

    ArcGIS Server's REST API root is ``…/rest/services`` — the parent
    ``…/rest`` path either 404s or returns an HTML index, both of which
    silently break the discovery walker. This helper avoids that footgun.
    """
    cleaned = url.rstrip("/")
    if _REST_ROOT_NEEDS_SERVICES.search(cleaned):
        return f"{cleaned}/services"
    return cleaned


async def _build_targets(
    ctx: Context,
    request: ScanRequest,
    *,
    console: Console | None = None,
) -> list[TargetRef]:
    token = ctx.cache.get("arcgis_token")
    normalized_url = normalize_rest_root(request.url)
    if normalized_url != request.url and console is not None:
        console.print(
            f"[dim]auto-corrected REST root: [cyan]{request.url}[/cyan] → "
            f"[cyan]{normalized_url}[/cyan][/dim]"
        )
    enumerator = ArcGISEnumerator(ctx.http, normalized_url, token=token)
    targets: list[TargetRef] = [
        TargetRef(url=enumerator.root_url, kind=TargetKind.ARCGIS_ROOT),
    ]
    folders: set[str] = set()
    services: list[ArcGISServiceRef] = []
    layer_count = 0
    try:
        async for service in enumerator.walk(max_depth=request.max_depth):
            services.append(service)
            if service.folder:
                folders.add(service.folder)
            prefix = f"{service.folder}/" if service.folder else ""
            targets.append(
                TargetRef(
                    url=service.url,
                    kind=TargetKind.ARCGIS_SERVICE,
                    service_path=f"{prefix}{service.name}/{service.type}",
                )
            )
    except (httpx.HTTPError, OSError) as exc:
        ctx.logger.warning("arcgis.discovery.failed", error=str(exc))
        if console is not None:
            console.print(f"[red]discovery failed:[/red] {exc}")
        return targets

    for service in services:
        try:
            layer_targets = [
                TargetRef(
                    url=layer.url,
                    kind=TargetKind.ARCGIS_LAYER,
                    service_path=f"{service.name}/{service.type}",
                    layer_id=layer.layer_id,
                )
                async for layer in enumerator.layers(service)
            ]
        except (httpx.HTTPError, OSError) as exc:
            ctx.logger.debug("arcgis.layer_enum.failed", url=service.url, error=str(exc))
            continue
        layer_count += len(layer_targets)
        targets.extend(layer_targets)

    if console is not None:
        if not services:
            console.print(
                "[yellow]⚠ Discovery returned no services. The URL may be "
                "wrong; try appending [cyan]/services[/cyan] to your REST root, "
                "or check that anonymous enumeration is allowed.[/yellow]"
            )
        else:
            console.print(
                f"[dim]🔎 Discovered [bold]{len(services)}[/bold] service(s) and "
                f"[bold]{layer_count}[/bold] layer(s) across "
                f"[bold]{len(folders) or 1}[/bold] folder(s); running "
                f"checks…[/dim]"
            )
    return targets


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


def _derive_portal_url(rest_url: str) -> str:
    """Derive a portal root from an ArcGIS REST URL."""
    if "/rest/services" in rest_url:
        return rest_url.split("/rest/services", 1)[0]
    return rest_url.rstrip("/")
