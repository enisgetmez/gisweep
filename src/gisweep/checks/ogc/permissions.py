"""OGC-005 — WFS Transactional (WFS-T) operations exposed without auth.

A WFS service that advertises a ``Transaction`` operation in its
GetCapabilities document is willing to accept feature inserts/updates/deletes.
When the endpoint is reachable without authentication, this is the OGC
equivalent of ARC-002 and is treated with the same severity. Verification
through an actual write attempt would require ``--active`` mode and lands
alongside the active ARC-002 verification path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.arcgis._helpers import has_anonymous_token
from gisweep.checks.ogc._helpers import cached_capabilities
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context

_TRANSACTION_OPERATIONS: frozenset[str] = frozenset({"Transaction", "LockFeature"})


@register(
    id="OGC-005",
    title="WFS Transactional operations exposed without authentication",
    description=(
        "The WFS endpoint advertises ``Transaction`` (and possibly "
        "``LockFeature``) in its OperationsMetadata, meaning anonymous "
        "callers may be able to insert, update, or delete features. Confirm "
        "with an authenticated curl probe — or run gisweep in ``--active`` "
        "mode — before treating this as exploited."
    ),
    category="ogc",
    severity=Severity.CRITICAL,
    cwe="CWE-862",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    kvkk=("m12",),
    gdpr=("art32", "art5-1-f"),
    references=("https://www.ogc.org/standards/wfs",),
    target_kinds=("ogc_service",),
    needs_active=False,
    can_verify_active=True,
    tags=("anonymous", "write", "ogc", "wfs-t"),
)
class WfsTransactionalCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_SERVICE:
            return
        if not has_anonymous_token(ctx):
            return
        for cap in cached_capabilities(ctx):
            if cap.endpoint_url != target.url or cap.service != "WFS":
                continue
            transactional_ops = cap.operations & _TRANSACTION_OPERATIONS
            if not transactional_ops:
                continue
            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                target=target,
                description=(
                    f"`{cap.endpoint_url}` advertises {', '.join(sorted(transactional_ops))} "
                    f"in its WFS {cap.version} OperationsMetadata. The endpoint was "
                    "reached without authentication, so anonymous callers may be able to "
                    "insert, modify, or delete features."
                ),
                evidence=Evidence(
                    matched=",".join(sorted(transactional_ops)),
                    notes=[
                        f"wfs_version={cap.version}",
                        f"feature_types={len(cap.layers)}",
                        f"operations={','.join(sorted(cap.operations))}",
                    ],
                ),
                remediation=(
                    "Restrict WFS-T to authenticated, role-scoped users. In "
                    "GeoServer this is configured via Security → Data → Service "
                    "Access Rules; in MapServer/QGIS Server, gate the endpoint "
                    "with a token-aware reverse proxy."
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
