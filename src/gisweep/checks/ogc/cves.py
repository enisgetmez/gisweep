"""OGC-002 — Outdated open-source OGC server with known CVEs.

Re-uses the bundled CVE database (:mod:`gisweep.cve`) but looks up the
software fingerprint extracted by the OGC discovery walker — currently
GeoServer, MapServer, QGIS Server, and deegree.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.ogc._helpers import cached_capabilities
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.cve import CveSeverity, get_cve_database

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.cve.db import CveRecord
    from gisweep.discovery.ogc_enum import OgcCapabilities


_PRODUCT_KEY: dict[str, str] = {
    "geoserver": "osgeo:geoserver",
    "mapserver": "osgeo:mapserver",
    "qgis_server": "qgis:qgis",
    "deegree": "deegree:deegree",
}

_SEVERITY_MAP: dict[CveSeverity, Severity] = {
    CveSeverity.NONE: Severity.INFO,
    CveSeverity.LOW: Severity.LOW,
    CveSeverity.MEDIUM: Severity.MEDIUM,
    CveSeverity.HIGH: Severity.HIGH,
    CveSeverity.CRITICAL: Severity.CRITICAL,
}


@register(
    id="OGC-002",
    title="Outdated open-source OGC server with known CVE",
    description=(
        "The fingerprinted server software (GeoServer / MapServer / QGIS "
        "Server / deegree) reports a version that falls within the affected "
        "range of one or more public CVEs. Recent GeoServer advisories include "
        "remote code-execution paths (for example CVE-2024-36401), so unpatched "
        "deployments are particularly high-risk."
    ),
    category="ogc",
    severity=Severity.MEDIUM,
    cwe="CWE-1395",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://geoserver.org/announcements/",
        "https://mapserver.org/development/changelog/changelog.html",
    ),
    target_kinds=("ogc_service",),
    tags=("cve", "outdated", "patch-management", "ogc"),
)
class OutdatedOgcServerCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_SERVICE:
            return
        capability = next(
            (c for c in cached_capabilities(ctx) if c.endpoint_url == target.url),
            None,
        )
        if capability is None:
            return
        software = capability.fingerprint.software
        version = capability.fingerprint.version
        if software not in _PRODUCT_KEY or not version:
            return

        database = get_cve_database()
        if database.is_empty():
            ctx.logger.debug("ogc002.cve_db_empty")
            return

        product_key = _PRODUCT_KEY[software]
        for record in database.matching(product_key, version):
            yield self._record_to_finding(record, software, version, capability, target, ctx)

    def _record_to_finding(
        self,
        record: CveRecord,
        software: str,
        version: str,
        capability: OgcCapabilities,
        target: TargetRef,
        ctx: Context,
    ) -> Finding:
        severity = _SEVERITY_MAP.get(record.severity, Severity.MEDIUM)
        return Finding(
            check_id=self.meta.id,
            title=f"{software.capitalize()} {version} affected by {record.cve_id}",
            severity=severity,
            target=target,
            description=(
                f"`{capability.endpoint_url}` runs {software} {version} which is "
                f"affected by {record.cve_id}: {record.summary.strip()}"
            ),
            evidence=Evidence(
                matched=f"{software}={version}",
                notes=[
                    f"cve_id={record.cve_id}",
                    f"signature={capability.fingerprint.raw_signature!r}",
                    f"cvss_score={record.cvss_score!r}",
                    f"cvss_vector={record.cvss_vector!r}",
                ],
            ),
            remediation=(
                f"Upgrade {software} past the fixed version listed in "
                f"{record.cve_id}. For GeoServer, security releases are "
                "published on geoserver.org/announcements; for MapServer, in "
                "the official changelog."
            ),
            references=[*list(self.meta.references), *list(record.references)],
            cwe=self.meta.cwe,
            cvss_vector=record.cvss_vector,
            cvss_score=record.cvss_score,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=[*list(self.meta.tags), software, record.cve_id],
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
