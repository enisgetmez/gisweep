"""ARC-011 / ARC-012 — bulk data-exfiltration capabilities on ArcGIS services.

* ARC-011 fires when a FeatureService advertises ``Sync`` or ``Extract`` —
  features that let any client mirror the layer wholesale, often with no
  pagination cap.
* ARC-012 fires when a MapServer advertises ``ExportTiles`` — letting any
  client harvest the tile cache for offline use.

Both checks run on the *service* target rather than per-layer, since the
capabilities live on the parent service descriptor.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from gisweep.checks.arcgis._helpers import has_anonymous_token
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.discovery.arcgis_enum import ArcGISEnumerator, _parse_capabilities

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


_SYNC_CAPABILITIES: frozenset[str] = frozenset({"Sync", "Extract"})
_EXPORT_TILES_CAPABILITIES: frozenset[str] = frozenset({"ExportTiles", "TilesOnly"})


async def _fetch_service_info(ctx: Context, service_url: str) -> dict[str, object] | None:
    cache_key = f"arcgis_service_info:{service_url}"
    cached = ctx.cache.get(cache_key)
    if isinstance(cached, dict):
        return cached
    token = ctx.cache.get("arcgis_token")
    enumerator = ArcGISEnumerator(ctx.http, service_url, token=token)
    url = enumerator.with_query(service_url)
    try:
        response = await ctx.http.get(url)
        response.raise_for_status()
    except (httpx.HTTPError, OSError) as exc:
        ctx.logger.debug("arcgis.service_info.failed", url=service_url, error=str(exc))
        return None
    payload = response.json()
    if not isinstance(payload, dict):
        return None
    ctx.cache[cache_key] = payload
    return payload


@register(
    id="ARC-011",
    title="FeatureService Sync/Extract enabled — bulk data exfiltration vector",
    description=(
        "The FeatureService advertises ``Sync`` or ``Extract`` capability. Either "
        "lets a caller download the full feature set in a single request and is a "
        "common large-scale data-exfil path when the service is reachable without "
        "authentication."
    ),
    category="arcgis",
    severity=Severity.MEDIUM,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/rest/services-reference/feature-service.htm",),
    target_kinds=("arcgis_service",),
    tags=("data-exposure", "exfil", "sync"),
)
class FeatureServiceSyncCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_SERVICE:
            return
        if "FeatureServer" not in target.url:
            return
        info = await _fetch_service_info(ctx, target.url)
        if info is None:
            return
        caps = _parse_capabilities(info)
        sync_caps = caps & _SYNC_CAPABILITIES
        if not sync_caps:
            return
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{target.url}` advertises {', '.join(sorted(sync_caps))} capability. "
                "An anonymous client can pull the full feature set with a single "
                "``createReplica`` (Sync) or ``extractData`` request, sidestepping any "
                "per-query record cap configured for the layer."
            ),
            evidence=Evidence(
                matched=",".join(sorted(sync_caps)),
                notes=[f"capabilities={','.join(sorted(caps))}"],
            ),
            remediation=(
                "Disable Sync / Extract unless the service is intentionally a public "
                "data download channel. Sync requires an editable layer; consider "
                "publishing a non-editable derivative for read-only consumers and "
                "gating the Sync-enabled service behind authentication."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            cvss_vector=self.meta.cvss_vector,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


@register(
    id="ARC-012",
    title="MapServer ExportTiles enabled — bulk tile-cache harvest",
    description=(
        "The MapServer advertises ``ExportTiles`` capability, allowing any caller "
        "to package and download the entire tile cache for offline reuse. Where "
        "the map data is licensed or sensitive, this is a quiet exfil path."
    ),
    category="arcgis",
    severity=Severity.LOW,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    kvkk=(),
    gdpr=(),
    references=("https://developers.arcgis.com/rest/services-reference/export-tiles.htm",),
    target_kinds=("arcgis_service",),
    tags=("data-exposure", "tiles"),
)
class ExportTilesEnabledCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_SERVICE:
            return
        if "MapServer" not in target.url and "ImageServer" not in target.url:
            return
        if not has_anonymous_token(ctx):
            return
        info = await _fetch_service_info(ctx, target.url)
        if info is None:
            return
        caps = _parse_capabilities(info)
        export_caps = caps & _EXPORT_TILES_CAPABILITIES
        if not export_caps:
            return
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{target.url}` advertises {', '.join(sorted(export_caps))} so an "
                "anonymous caller can package and download the tile cache. If the "
                "underlying basemap is licensed (e.g. Esri World Imagery, Mapbox), "
                "this constitutes a license violation in addition to a data leak."
            ),
            evidence=Evidence(
                matched=",".join(sorted(export_caps)),
                notes=[f"capabilities={','.join(sorted(caps))}"],
            ),
            remediation=(
                "Disable ExportTiles in ArcGIS Server Manager (Service Properties → "
                "Capabilities). If bulk download is genuinely needed, expose it as a "
                "separate authenticated endpoint with audit logging."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            cvss_vector=self.meta.cvss_vector,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
