"""Auth/permission checks: ARC-002 (anonymous write) and ARC-003 (admin exposed)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from gisweep.checks.arcgis._helpers import (
    fetch_layer_info,
    has_anonymous_token,
)
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.discovery.arcgis_enum import _parse_capabilities

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context

_WRITE_CAPABILITIES: frozenset[str] = frozenset({"Create", "Update", "Delete", "Editing"})

_ADMIN_PATH_FRAGMENTS: tuple[tuple[str, str], ...] = (
    ("/rest/services", "/admin"),
    ("/rest/services", "/admin/"),
    ("/rest/services", "/portaladmin"),
    ("/rest/services", "/portaladmin/"),
)


@register(
    id="ARC-002",
    title="Anonymous write capability on FeatureServer layer",
    description=(
        "The FeatureServer layer advertises Create/Update/Delete capabilities and "
        "is reachable without authentication. Passive detection inspects the "
        "layer's ``capabilities`` flag — confirmation requires running the "
        "check in ``--active`` mode, which performs an atomic add+delete of a "
        "single test feature at Null Island."
    ),
    category="arcgis",
    severity=Severity.CRITICAL,
    cwe="CWE-862",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    kvkk=("m12",),
    gdpr=("art32", "art5-1-f"),
    references=("https://developers.arcgis.com/rest/services-reference/feature-service.htm",),
    needs_active=False,
    can_verify_active=True,
    target_kinds=("arcgis_layer",),
    tags=("anonymous", "write", "permission"),
)
class AnonymousWriteCapabilityCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_LAYER:
            return
        if not has_anonymous_token(ctx):
            return
        try:
            info = await fetch_layer_info(ctx, target.url)
        except Exception as exc:
            ctx.logger.debug("arc002.fetch_failed", url=target.url, error=str(exc))
            return
        caps = _parse_capabilities(info)
        write_caps = caps & _WRITE_CAPABILITIES
        if not write_caps:
            return
        layer_name = str(info.get("name") or "")
        notes = [
            f"capabilities={','.join(sorted(caps))}",
            f"writable={','.join(sorted(write_caps))}",
        ]
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"Layer `{layer_name}` at `{target.url}` advertises write "
                f"capabilities (`{', '.join(sorted(write_caps))}`) and was reached without "
                "authentication. An attacker may be able to insert, modify, or delete "
                "features. Re-run with ``--active --i-own-this-target`` to confirm with an "
                "atomic add/delete probe."
            ),
            evidence=Evidence(matched=",".join(sorted(write_caps)), notes=notes),
            remediation=(
                "Restrict editing to authenticated, role-scoped users. In ArcGIS Server, "
                "configure the FeatureServer service security so anonymous role lacks Edit, "
                "or front the service with a token-aware reverse proxy. If the layer is "
                "intentionally public-write (e.g. citizen reporting), gate it with rate "
                "limiting and a moderation queue."
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
    id="ARC-003",
    title="ArcGIS admin endpoint reachable",
    description=(
        "ArcGIS Server's ``/admin/`` and Portal's ``/portaladmin/`` endpoints "
        "expose privileged operations (security configuration, service "
        "publishing, log access). When reachable without IP allow-listing or "
        "VPN, they substantially widen the blast radius of any credential "
        "leak."
    ),
    category="arcgis",
    severity=Severity.CRITICAL,
    cwe="CWE-284",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://enterprise.arcgis.com/en/server/latest/administer/linux/about-arcgis-server-administrator-directory.htm",
    ),
    target_kinds=("arcgis_root",),
    tags=("admin", "exposure"),
)
class AdminEndpointExposedCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return
        admin_urls = _candidate_admin_urls(target.url)
        for admin_url in admin_urls:
            try:
                response = await ctx.http.get(admin_url)
            except (httpx.HTTPError, OSError) as exc:
                ctx.logger.debug("arc003.fetch_failed", url=admin_url, error=str(exc))
                continue
            if not _looks_reachable(response):
                continue
            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                target=TargetRef(url=admin_url, kind=TargetKind.ARCGIS_ROOT),
                description=(
                    f"`{admin_url}` is reachable from the public internet (HTTP "
                    f"{response.status_code}) and serves the ArcGIS administrator "
                    "directory. Even with credential prompts, exposure of this surface "
                    "enables credential brute-force and intelligence gathering."
                ),
                evidence=Evidence(
                    matched=f"HTTP {response.status_code}",
                    notes=[
                        f"status={response.status_code}",
                        f"server={response.headers.get('server', '')}",
                        f"content_type={response.headers.get('content-type', '')}",
                    ],
                ),
                remediation=(
                    "Move the admin directory behind an allow-list, VPN, or service mesh. "
                    "Disable the public ``/admin`` endpoint in production; ArcGIS lets you "
                    "deploy a separate web adaptor that excludes the administrator routes."
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


_REACHABLE_STATUSES: frozenset[int] = frozenset({200, 301, 302, 401, 403})
_HTTP_OK = 200


def _looks_reachable(response: httpx.Response) -> bool:
    if response.status_code not in _REACHABLE_STATUSES:
        return False
    body = response.text.lower() if response.content else ""
    return not (response.status_code == _HTTP_OK and not _admin_signature(body))


def _admin_signature(body: str) -> bool:
    return any(
        token in body
        for token in (
            "arcgis server administrator",
            "siteadmin",
            "portal administrator",
            "/admin/security",
            "rest admin api",
        )
    )


def _candidate_admin_urls(root_url: str) -> list[str]:
    candidates: set[str] = set()
    for needle, replacement in _ADMIN_PATH_FRAGMENTS:
        if needle in root_url:
            candidates.add(root_url.replace(needle, replacement, 1).rstrip("/"))
    return sorted(candidates)
