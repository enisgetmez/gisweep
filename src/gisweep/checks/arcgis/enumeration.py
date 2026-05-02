"""ARC-001 — Anonymous service enumeration.

ArcGIS REST roots that respond to ``/rest/services?f=json`` without auth let
any caller list every service and folder available on the server. This is
informational on its own — service indexes are sometimes intentionally
public — but it is the gateway finding that justifies running the rest of
the catalogue.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.arcgis._helpers import fetch_root_info, has_anonymous_token
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


@register(
    id="ARC-001",
    title="Anonymous ArcGIS service enumeration",
    description=(
        "The ArcGIS REST root responds to unauthenticated ``f=json`` requests "
        "and returns the list of services and folders. Verify this index is "
        "intended to be public; otherwise enforce authentication or restrict "
        "access at the network edge."
    ),
    category="arcgis",
    severity=Severity.INFO,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/rest/services-reference/",),
    target_kinds=("arcgis_root",),
)
class AnonymousServiceEnumerationCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return
        if not has_anonymous_token(ctx):
            return
        try:
            info = await fetch_root_info(ctx, target.url)
        except Exception as exc:
            ctx.logger.debug("arc001.fetch_failed", url=target.url, error=str(exc))
            return
        services = info.get("services") or []
        folders = info.get("folders") or []
        if not services and not folders:
            return
        version = info.get("currentVersion")
        notes = [
            f"services_count={len(services)}",
            f"folders_count={len(folders)}",
        ]
        if version:
            notes.append(f"current_version={version}")
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"ArcGIS REST root at `{target.url}` exposes "
                f"{len(services)} services and {len(folders)} folders to unauthenticated callers."
            ),
            evidence=Evidence(matched=f"{len(services)} services", notes=notes),
            remediation=(
                "If this index is not meant to be public, place the REST endpoint behind "
                "authentication via ArcGIS Server token, the web tier, or a reverse proxy. "
                "When the listing must remain public, ensure individual services do not "
                "expose data that triggers ARC-002 / ARC-013 / ARC-014."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            cvss_vector=self.meta.cvss_vector,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=["anonymous", "enumeration"],
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
