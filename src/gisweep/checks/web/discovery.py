"""WEB-001 — embedded map data-plane endpoint inventory.

Walks the network log captured by the Playwright crawler and surfaces every
ArcGIS REST / WMS / WFS / Mapbox / Google Maps / tile XYZ endpoint that the
page actually used. The finding is informational on its own (the inventory
itself is not a vulnerability) but it gives the operator the URL list to
hand to ``gisweep arcgis``, ``gisweep ogc``, or ``gisweep secrets`` for the
follow-up scan.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.web._helpers import cached_discovery
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.discovery.library_detect import classify_endpoint

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


@register(
    id="WEB-001",
    title="Embedded map data-plane endpoints",
    description=(
        "The page loaded one or more GIS data-plane endpoints (ArcGIS REST, "
        "OGC WMS/WFS, Mapbox API, Google Maps API, or XYZ tile services). "
        "This finding inventories them so the operator can target each one "
        "with the dedicated subcommand."
    ),
    category="web",
    severity=Severity.INFO,
    cwe="CWE-200",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(),
    target_kinds=("web_page",),
    tags=("web", "discovery", "endpoint-inventory"),
)
class EmbeddedEndpointInventoryCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None:
            return
        endpoints: dict[str, list[str]] = {}
        for req in result.requests:
            kind = classify_endpoint(req.url)
            if kind is None:
                continue
            endpoints.setdefault(kind, []).append(req.url)
        if not endpoints:
            return
        sample_size = 3
        notes: list[str] = []
        for kind in sorted(endpoints):
            unique_urls = sorted(set(endpoints[kind]))
            sample = ", ".join(unique_urls[:sample_size])
            extra = (
                f" (+{len(unique_urls) - sample_size} more)"
                if len(unique_urls) > sample_size
                else ""
            )
            notes.append(f"{kind}={len(unique_urls)} → {sample}{extra}")
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{result.final_url}` loaded {sum(len(v) for v in endpoints.values())} "
                f"GIS data-plane request(s) across {len(endpoints)} endpoint kind(s). "
                "Re-run gisweep against each one to audit the underlying service."
            ),
            evidence=Evidence(
                matched=", ".join(sorted(endpoints)),
                notes=notes,
            ),
            remediation=(
                "Inventory the listed endpoints. For ArcGIS REST and OGC services run "
                "`gisweep arcgis` / `gisweep ogc` against them; for Mapbox / Google "
                "Maps confirm the API key is restricted to the production domain via "
                "the vendor console."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
