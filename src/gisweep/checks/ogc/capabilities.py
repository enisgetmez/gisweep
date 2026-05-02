"""OGC-001 — Anonymous WMS/WFS GetCapabilities accessible.

OGC services often publish a full layer / feature-type catalogue without
authentication. That is sometimes intentional (open public data) and
sometimes a misconfiguration; the check raises an info-level finding so the
operator can confirm and so subsequent OGC-* checks have a documented
reason for firing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.ogc._helpers import cached_capabilities
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


@register(
    id="OGC-001",
    title="Anonymous WMS/WFS GetCapabilities",
    description=(
        "The endpoint responds to ``GetCapabilities`` without authentication "
        "and exposes the full service catalogue. Confirm this listing is "
        "intended to be public; otherwise place the service behind an auth "
        "gate or restrict it at the network edge."
    ),
    category="ogc",
    severity=Severity.INFO,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://www.ogc.org/standards/wms",
        "https://www.ogc.org/standards/wfs",
    ),
    target_kinds=("ogc_service",),
    tags=("anonymous", "enumeration", "ogc"),
)
class AnonymousGetCapabilitiesCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_SERVICE:
            return
        for cap in cached_capabilities(ctx):
            if cap.endpoint_url != target.url:
                continue
            yield Finding(
                check_id=self.meta.id,
                title=f"{self.meta.title} ({cap.service} {cap.version})",
                severity=self.meta.severity,
                target=target,
                description=(
                    f"`{cap.endpoint_url}` exposes a {cap.service} "
                    f"{cap.version} capabilities document with "
                    f"{len(cap.layers)} layer(s)/feature-type(s) accessible "
                    "without authentication."
                ),
                evidence=Evidence(
                    matched=f"{cap.service} {cap.version}",
                    notes=[
                        f"software={cap.fingerprint.software}",
                        f"software_version={cap.fingerprint.version!r}",
                        f"layer_count={len(cap.layers)}",
                        f"operations={','.join(sorted(cap.operations)) or 'unknown'}",
                    ],
                ),
                remediation=(
                    "If this catalogue is not meant to be public, place the OGC "
                    "endpoint behind an authentication proxy. When publication "
                    "is required, ensure layer-level access control is enforced "
                    "and confirm no PII is exposed via ``GetFeature`` queries."
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
