"""ARC-004 — vendor default ArcGIS Server / Portal credentials accepted.

Gated behind both ``--active`` and ``--auth-bruteforce``. Probes a tiny
fixed list of vendor-default username/password pairs against the portal's
``generateToken`` endpoint, stops after the first success or three
failures (whichever comes first), records every attempt to the audit log,
and never sleeps the loop tighter than the configured per-host rate limit
so we don't accidentally trip a lockout policy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from gisweep.audit import AuditEntry, AuditOutcome, write_audit_entry
from gisweep.auth.arcgis_token import sharing_token_url
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


# Vendor defaults ONLY. Adding any custom wordlist is out of scope for this
# check by design — operators who want broader credential testing should
# point a dedicated tool (e.g. patator, hydra) under written authorization.
_DEFAULT_CREDENTIALS: tuple[tuple[str, str], ...] = (
    ("siteadmin", "siteadmin"),
    ("admin", "admin"),
    ("esri", "esri"),
)
_MAX_ATTEMPTS = 3


def _portal_root(rest_root: str) -> str:
    """Strip the REST suffix to get the portal/server root for token endpoint."""
    for suffix in ("/rest/services", "/rest"):
        idx = rest_root.find(suffix)
        if idx != -1:
            return rest_root[:idx]
    return rest_root.rstrip("/")


@register(
    id="ARC-004",
    title="ArcGIS portal accepts vendor default credentials",
    description=(
        "The portal's ``/sharing/rest/generateToken`` endpoint returned a valid "
        "token for one of the vendor-default credential pairs (siteadmin/"
        "siteadmin, admin/admin, esri/esri). Anyone on the internet can take "
        "full control of the deployment. The check is opt-in twice — both "
        "``--active`` and ``--auth-bruteforce`` are required — and stops after "
        "three attempts to avoid triggering a lockout policy."
    ),
    category="arcgis",
    severity=Severity.CRITICAL,
    cwe="CWE-521",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://enterprise.arcgis.com/en/portal/latest/administer/linux/about-the-portal-administrator-account.htm",
    ),
    target_kinds=("arcgis_root",),
    needs_active=True,
    can_verify_active=True,
    tags=("active", "credentials", "default-creds"),
)
class DefaultCredentialsCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return
        opts = ctx.options
        if not (opts.active and opts.auth_bruteforce):
            return
        if not opts.i_own_this_target:
            ctx.logger.warning("arc004.skipped.no_ownership_flag", url=target.url)
            return

        portal = _portal_root(target.url)
        token_url = sharing_token_url(portal)
        operator = opts.auth.referer if opts.auth and opts.auth.referer else "owner-attestation"

        for username, password in _DEFAULT_CREDENTIALS[:_MAX_ATTEMPTS]:
            outcome, token = await _try_credential(ctx, token_url, username, password)
            write_audit_entry(
                AuditEntry(
                    scan_id=ctx.scan_id,
                    check_id=self.meta.id,
                    action="default-cred-probe",
                    target_url=token_url,
                    outcome=outcome,
                    operator=operator,
                    details={
                        "username": username,
                        # password redacted automatically by the audit module
                        "password": password,
                        "issued_token": token,
                    },
                )
            )
            if outcome is AuditOutcome.SUCCESS:
                yield Finding(
                    check_id=self.meta.id,
                    title=self.meta.title,
                    severity=self.meta.severity,
                    target=TargetRef(url=token_url, kind=TargetKind.ARCGIS_ROOT),
                    description=(
                        f"`{token_url}` issued a valid token for the vendor-default "
                        f"credential pair `{username}` / `{password}`. The deployment "
                        "must be considered fully compromised; rotate every account, "
                        "revoke active tokens, and audit logs for prior abuse."
                    ),
                    evidence=Evidence(
                        matched=f"{username}:<accepted>",
                        notes=[
                            f"username={username}",
                            "password=<vendor-default; see audit log>",
                            "token=<redacted; see audit log>",
                        ],
                    ),
                    remediation=(
                        "Reset the matching account immediately, then audit "
                        "ArcGIS Server / Portal logs for prior token issuance "
                        "to the same username. Consider IP allow-listing the "
                        "admin endpoint and disabling the ``/sharing/rest/"
                        "generateToken`` endpoint for built-in users."
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
                # Stop after first hit to minimise lockout risk.
                return


async def _try_credential(
    ctx: Context,
    token_url: str,
    username: str,
    password: str,
) -> tuple[AuditOutcome, str | None]:
    payload = {
        "username": username,
        "password": password,
        "client": "referer",
        "referer": "https://www.arcgis.com",
        "expiration": "5",
        "f": "json",
    }
    try:
        response = await ctx.http.post(token_url, data=payload)
    except (httpx.HTTPError, OSError):
        return AuditOutcome.FAILURE, None
    try:
        body = response.json()
    except ValueError:
        return AuditOutcome.FAILURE, None
    if isinstance(body, dict) and isinstance(body.get("token"), str):
        return AuditOutcome.SUCCESS, str(body["token"])
    return AuditOutcome.FAILURE, None
