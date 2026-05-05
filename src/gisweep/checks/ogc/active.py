"""Active GeoServer-specific checks gated by ``--active --i-own-this-target``.

Currently:

* **GEO-001** — CVE-2024-36401: pre-2.23.6 / 2.24.4 / 2.25.2 GeoServers
  evaluate ``valueReference`` in ``GetPropertyValue`` requests through the
  OGC filter evaluator, which permits arbitrary Java method invocations.
  Public PoCs hand the call ``exec(Runtime.getRuntime(),'id')`` and get
  RCE. We deliberately do **not** call ``exec`` — instead we send a
  side-effect-free expression
  (``Runtime.getRuntime().getClass().getName()``) that still hits the
  vulnerable code path. A patched server rejects it; an unpatched server
  echoes back ``java.lang.Runtime``.

The probe is opt-in twice (``--active`` AND ``--i-own-this-target``) and
every invocation is appended to ``~/.gisweep/audit.jsonl`` with the
operator handle and the safe payload that was sent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from gisweep.audit import AuditEntry, AuditOutcome, write_audit_entry
from gisweep.checks.ogc._helpers import cached_capabilities
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


_HTTP_OK = 200
# A side-effect-free expression that triggers the same evaluation path as the
# RCE PoC. A patched GeoServer (>= 2.23.6 / 2.24.4 / 2.25.2) rejects this with
# an error; a vulnerable one returns the literal class name.
_SAFE_PROBE_VALUE_REFERENCE = "Runtime.getRuntime().getClass().getName()"
_VULNERABLE_MARKER = "java.lang.Runtime"


@register(
    id="GEO-001",
    title="GeoServer evaluates unsafe expressions in OGC filter (CVE-2024-36401)",
    description=(
        "The GeoServer at this endpoint evaluates ``valueReference`` in "
        "``GetPropertyValue`` requests through the OGC filter evaluator, "
        "which (pre-fix) permits arbitrary Java method invocations. The "
        "public PoC for this issue achieves unauthenticated RCE by passing "
        "``exec(Runtime.getRuntime(),'id')``. We sent the side-effect-free "
        "probe ``Runtime.getRuntime().getClass().getName()`` and the server "
        "returned the literal ``java.lang.Runtime`` — confirming the "
        "vulnerable code path is reachable without authentication."
    ),
    category="ogc",
    severity=Severity.CRITICAL,
    cwe="CWE-94",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://nvd.nist.gov/vuln/detail/CVE-2024-36401",
        "https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv",
    ),
    target_kinds=("ogc_service",),
    needs_active=True,
    can_verify_active=True,
    tags=("active", "ogc", "rce", "cve-2024-36401"),
)
class GeoServerCve202436401Check(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_SERVICE:
            return
        opts = ctx.options
        if not (opts.active and opts.i_own_this_target):
            return

        capabilities = cached_capabilities(ctx)
        cap = next(
            (c for c in capabilities if c.endpoint_url == target.url and c.layers),
            None,
        )
        if cap is None or cap.fingerprint.software != "geoserver":
            return
        type_name = next((layer.name for layer in cap.layers if layer.name), None)
        if not type_name:
            return

        operator = (
            ctx.options.auth.username
            if ctx.options.auth and ctx.options.auth.username
            else "i-own-this-target"
        )

        params = {
            "SERVICE": "WFS",
            "VERSION": "2.0.0",
            "REQUEST": "GetPropertyValue",
            "TYPENAMES": type_name,
            "valueReference": _SAFE_PROBE_VALUE_REFERENCE,
        }

        try:
            response = await ctx.http.get(target.url, params=params)
        except (httpx.HTTPError, OSError) as exc:
            write_audit_entry(
                AuditEntry(
                    scan_id=ctx.scan_id,
                    check_id=self.meta.id,
                    action="cve-2024-36401-probe",
                    target_url=target.url,
                    outcome=AuditOutcome.FAILURE,
                    operator=operator,
                    details={
                        "type_name": type_name,
                        "value_reference": _SAFE_PROBE_VALUE_REFERENCE,
                        "error": str(exc),
                    },
                )
            )
            return

        body = response.text or ""
        if response.status_code != _HTTP_OK or _VULNERABLE_MARKER not in body:
            write_audit_entry(
                AuditEntry(
                    scan_id=ctx.scan_id,
                    check_id=self.meta.id,
                    action="cve-2024-36401-probe",
                    target_url=target.url,
                    outcome=AuditOutcome.SKIPPED,
                    operator=operator,
                    details={
                        "type_name": type_name,
                        "value_reference": _SAFE_PROBE_VALUE_REFERENCE,
                        "http_status": response.status_code,
                        "vulnerable_marker_seen": False,
                    },
                )
            )
            return

        write_audit_entry(
            AuditEntry(
                scan_id=ctx.scan_id,
                check_id=self.meta.id,
                action="cve-2024-36401-probe",
                target_url=target.url,
                outcome=AuditOutcome.SUCCESS,
                operator=operator,
                details={
                    "type_name": type_name,
                    "value_reference": _SAFE_PROBE_VALUE_REFERENCE,
                    "http_status": response.status_code,
                    "vulnerable_marker_seen": True,
                },
            )
        )

        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=self.meta.description,
            evidence=Evidence(
                matched=f"{_VULNERABLE_MARKER} echoed back from GetPropertyValue",
                notes=[
                    f"feature_type={type_name}",
                    f"value_reference={_SAFE_PROBE_VALUE_REFERENCE}",
                    f"http_status={response.status_code}",
                    "rce_not_executed=true",
                ],
            ),
            remediation=(
                "Upgrade GeoServer to 2.23.6 / 2.24.4 / 2.25.2 (or any later "
                "release in the corresponding branch). If immediate upgrade is "
                "impossible, apply the upstream mitigation that disables Java "
                "method evaluation in the OGC filter evaluator. Treat the "
                "server as compromised until you have audited request logs for "
                "the exposure window — public PoC + zero authentication = high "
                "likelihood of in-the-wild exploitation."
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
