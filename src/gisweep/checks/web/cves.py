"""WEB-007 — outdated client-side GIS library with known CVE."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.web._helpers import cached_discovery
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.cve import CveSeverity, get_cve_database

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.cve.db import CveRecord
    from gisweep.discovery.library_detect import DetectedLibrary


_PRODUCT_KEY: dict[str, str] = {
    "leaflet": "leafletjs:leaflet",
    "openlayers": "openlayers:openlayers",
    "mapbox-gl": "mapbox:mapbox-gl-js",
    "cesium": "cesiumgs:cesium",
    "arcgis-js-api": "esri:arcgis_api_for_javascript",
}

_SEVERITY_MAP: dict[CveSeverity, Severity] = {
    CveSeverity.NONE: Severity.INFO,
    CveSeverity.LOW: Severity.LOW,
    CveSeverity.MEDIUM: Severity.MEDIUM,
    CveSeverity.HIGH: Severity.HIGH,
    CveSeverity.CRITICAL: Severity.CRITICAL,
}


@register(
    id="WEB-007",
    title="Outdated client-side GIS library with known CVE",
    description=(
        "A JavaScript GIS library detected on the page (Leaflet, OpenLayers, "
        "Mapbox GL, Cesium, or the ArcGIS API for JavaScript) reports a "
        "version that falls within the affected range of one or more public "
        "CVEs in the bundled NVD-sourced database."
    ),
    category="web",
    severity=Severity.MEDIUM,
    cwe="CWE-1395",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(),
    target_kinds=("web_page",),
    tags=("web", "cve", "outdated", "patch-management"),
)
class OutdatedJsLibraryCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None or not result.libraries:
            return
        database = get_cve_database()
        if database.is_empty():
            return
        for library in result.libraries:
            if library.version is None:
                continue
            product_key = _PRODUCT_KEY.get(library.name)
            if product_key is None:
                continue
            for record in database.matching(product_key, library.version):
                yield self._record_to_finding(record, library, target, ctx)

    def _record_to_finding(
        self,
        record: CveRecord,
        library: DetectedLibrary,
        target: TargetRef,
        ctx: Context,
    ) -> Finding:
        severity = _SEVERITY_MAP.get(record.severity, Severity.MEDIUM)
        return Finding(
            check_id=self.meta.id,
            title=f"{library.name} {library.version} affected by {record.cve_id}",
            severity=severity,
            target=target,
            description=(
                f"`{target.url}` loads {library.name} {library.version} "
                f"({library.source}) which is affected by {record.cve_id}: "
                f"{record.summary.strip()}"
            ),
            evidence=Evidence(
                matched=f"{library.name}={library.version}",
                notes=[
                    f"cve_id={record.cve_id}",
                    f"detection_source={library.source}",
                    f"evidence={library.evidence}",
                    f"cvss_score={record.cvss_score!r}",
                ],
            ),
            remediation=(
                f"Bump {library.name} past the fixed version listed in {record.cve_id}, "
                "redeploy the bundle, and clear the CDN cache so users actually receive "
                "the patched build."
            ),
            references=list(record.references),
            cwe=self.meta.cwe,
            cvss_vector=record.cvss_vector,
            cvss_score=record.cvss_score,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=[*list(self.meta.tags), library.name, record.cve_id],
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
