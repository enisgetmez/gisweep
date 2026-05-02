"""ARC-015 — Outdated ArcGIS Server with known CVE.

The check reads ``currentVersion`` from the REST root's ``f=json`` payload and
matches it against the bundled CVE database (:mod:`gisweep.cve`). One Finding
is emitted per (server, CVE) pair that applies to the running version.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.arcgis._helpers import fetch_root_info
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.cve import CveSeverity, get_cve_database

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.cve.db import CveRecord


_PRODUCT_KEY = "esri:arcgis_server"
_DOTTED_PARTS = 2
_PATCH_DIGIT_COUNT = 2


def normalize_arcgis_server_version(raw: str) -> str:
    """Translate ArcGIS Server's compact ``currentVersion`` form to the
    standard semver string used in NVD CVE entries.

    Esri historically reports the running version in a concatenated form
    (``10.91`` for 10.9.1, ``10.31`` for 10.3.1) but documents and CVEs use
    the dotted form. The 11.x line uses the dotted form natively, so the
    transformation only fires for ``10.<two-digit>`` inputs.
    """
    cleaned = raw.strip()
    parts = cleaned.split(".")
    if (
        len(parts) == _DOTTED_PARTS
        and parts[0] == "10"
        and len(parts[1]) == _PATCH_DIGIT_COUNT
        and parts[1].isdigit()
    ):
        return f"10.{parts[1][0]}.{parts[1][1]}"
    return cleaned


_SEVERITY_MAP: dict[CveSeverity, Severity] = {
    CveSeverity.NONE: Severity.INFO,
    CveSeverity.LOW: Severity.LOW,
    CveSeverity.MEDIUM: Severity.MEDIUM,
    CveSeverity.HIGH: Severity.HIGH,
    CveSeverity.CRITICAL: Severity.CRITICAL,
}


@register(
    id="ARC-015",
    title="Outdated ArcGIS Server with known CVE",
    description=(
        "The reported ``currentVersion`` falls within the affected range of one "
        "or more public CVEs. Patches are typically available; the bundled CVE "
        "database is regenerated from NIST NVD via "
        "``scripts/refresh_cve_db.py``."
    ),
    category="arcgis",
    severity=Severity.MEDIUM,
    cwe="CWE-1395",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://www.esri.com/arcgis-blog/products/trust-arcgis/administration/security-advisories-and-bulletins/",
    ),
    target_kinds=("arcgis_root",),
    tags=("cve", "outdated", "patch-management"),
)
class OutdatedArcGISServerCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return
        try:
            info = await fetch_root_info(ctx, target.url)
        except Exception as exc:
            ctx.logger.debug("arc015.fetch_failed", url=target.url, error=str(exc))
            return
        raw_version = info.get("currentVersion")
        if raw_version is None:
            return
        raw_str = str(raw_version).strip()
        if not raw_str:
            return
        version_str = normalize_arcgis_server_version(raw_str)

        database = get_cve_database()
        if database.is_empty():
            ctx.logger.debug("arc015.cve_db_empty")
            return

        matches = database.matching(_PRODUCT_KEY, version_str)
        for record in matches:
            yield self._record_to_finding(record, version_str, target, ctx)

    def _record_to_finding(
        self,
        record: CveRecord,
        version: str,
        target: TargetRef,
        ctx: Context,
    ) -> Finding:
        severity = _SEVERITY_MAP.get(record.severity, Severity.MEDIUM)
        affected = ", ".join(_format_range(r) for r in record.ranges) or "unspecified"
        return Finding(
            check_id=self.meta.id,
            title=f"{self.meta.title} — {record.cve_id}",
            severity=severity,
            target=target,
            description=(
                f"ArcGIS Server reports ``currentVersion={version}`` which is "
                f"affected by {record.cve_id}: {record.summary.strip()}"
            ),
            evidence=Evidence(
                matched=f"version={version}",
                notes=[
                    f"cve_id={record.cve_id}",
                    f"affected_ranges={affected}",
                    f"cvss_score={record.cvss_score!r}",
                    f"cvss_vector={record.cvss_vector!r}",
                ],
            ),
            remediation=(
                f"Upgrade ArcGIS Server past the fixed version listed in "
                f"{record.cve_id}, and apply Esri's Trust Center security patch "
                "covering this CVE if one is available."
            ),
            references=[*list(self.meta.references), *list(record.references)],
            cwe=self.meta.cwe,
            cvss_vector=record.cvss_vector,
            cvss_score=record.cvss_score,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=[*list(self.meta.tags), record.cve_id],
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


def _format_range(r: object) -> str:
    introduced = getattr(r, "introduced", None)
    fixed = getattr(r, "fixed", None)
    if introduced and fixed:
        return f"[{introduced}, {fixed})"
    if fixed:
        return f"<{fixed}"
    if introduced:
        return f">={introduced}"
    return "*"
