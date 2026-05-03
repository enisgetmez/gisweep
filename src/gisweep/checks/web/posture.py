"""Browser-posture checks: WEB-003 (CORS), WEB-004 (mixed content),
WEB-005 (missing SRI), WEB-006 (iframe sandbox).

All four read the existing :class:`WebDiscoveryResult` populated by the
Playwright crawler — none of them issue extra browser navigations. WEB-003
does fire a single ``OPTIONS`` preflight per discovered API endpoint with a
synthetic ``Origin`` header, which is a vanilla CORS exchange that does not
mutate remote state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from gisweep.checks.web._helpers import cached_discovery
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.discovery.library_detect import classify_endpoint

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


_CORS_PROBE_ORIGIN = "https://gisweep-cors-probe.example"


def _same_origin(page_url: str, asset_url: str) -> bool:
    page = urlparse(page_url)
    asset = urlparse(asset_url)
    if not asset.netloc:
        return True
    return (page.scheme, page.netloc) == (asset.scheme, asset.netloc)


@register(
    id="WEB-003",
    title="Permissive CORS on a discovered data-plane endpoint",
    description=(
        "An ``OPTIONS`` preflight from an attacker-controlled origin received "
        "either a reflected ``Access-Control-Allow-Origin`` (any origin works) "
        "or ``Access-Control-Allow-Origin: *`` paired with "
        "``Access-Control-Allow-Credentials: true``. Either configuration lets "
        "any web page read the data plane in the user's browser."
    ),
    category="web",
    severity=Severity.HIGH,
    cwe="CWE-942",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",),
    target_kinds=("web_page",),
    tags=("web", "cors"),
)
class CorsMisconfigCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None:
            return

        seen: set[str] = set()
        for request in result.requests:
            if classify_endpoint(request.url) is None:
                continue
            if request.url in seen:
                continue
            seen.add(request.url)
            try:
                response = await ctx.http.options(
                    request.url,
                    headers={
                        "Origin": _CORS_PROBE_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    },
                )
            except (httpx.HTTPError, OSError) as exc:
                ctx.logger.debug("web003.options_failed", url=request.url, error=str(exc))
                continue
            allow_origin = response.headers.get("Access-Control-Allow-Origin")
            allow_credentials = (
                response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            )
            if allow_origin is None:
                continue

            reflected = allow_origin.strip() == _CORS_PROBE_ORIGIN
            wildcard_with_creds = allow_origin.strip() == "*" and allow_credentials
            if not (reflected or wildcard_with_creds):
                continue

            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=self.meta.severity,
                target=TargetRef(url=request.url, kind=TargetKind.ASSET),
                description=(
                    f"`{request.url}` returned "
                    f"``Access-Control-Allow-Origin: {allow_origin}``"
                    + (
                        " with ``Access-Control-Allow-Credentials: true``"
                        if allow_credentials
                        else ""
                    )
                    + ". Any origin can therefore read responses from this endpoint in "
                    "a victim's browser, including authenticated responses."
                ),
                evidence=Evidence(
                    matched=allow_origin,
                    notes=[
                        f"page_url={result.final_url}",
                        f"reflected={reflected}",
                        f"wildcard_with_credentials={wildcard_with_creds}",
                        f"probe_origin={_CORS_PROBE_ORIGIN}",
                    ],
                ),
                remediation=(
                    "Restrict ``Access-Control-Allow-Origin`` to the production "
                    "domain(s) the page is served from, and keep "
                    "``Access-Control-Allow-Credentials`` to ``true`` only when "
                    "absolutely required. Never reflect arbitrary origins."
                ),
                references=list(self.meta.references),
                cwe=self.meta.cwe,
                kvkk_articles=list(self.meta.kvkk),
                gdpr_articles=list(self.meta.gdpr),
                tags=list(self.meta.tags),
                discovered_at=datetime.now(tz=UTC),
                scan_id=ctx.scan_id,
            )


@register(
    id="WEB-004",
    title="Mixed content — HTTPS page loaded an HTTP resource",
    description=(
        "The page was served over HTTPS but loaded one or more resources over "
        "plain HTTP. Modern browsers either block the request or downgrade the "
        "page security indicator; in both cases the resource is open to "
        "tampering by anyone on the network path."
    ),
    category="web",
    severity=Severity.MEDIUM,
    cwe="CWE-319",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",),
    target_kinds=("web_page",),
    tags=("web", "mixed-content", "tls"),
)
class MixedContentCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None:
            return
        if not result.final_url.lower().startswith("https://"):
            return
        http_assets = sorted(
            {req.url for req in result.requests if req.url.lower().startswith("http://")}
        )
        if not http_assets:
            return
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{result.final_url}` loaded {len(http_assets)} resource(s) over "
                "plain HTTP while served over HTTPS. Browsers may block the requests "
                "outright or strip the security indicator; either way, the resources "
                "can be tampered with on the network path."
            ),
            evidence=Evidence(
                matched=", ".join(http_assets[:5]),
                notes=[
                    f"http_asset_count={len(http_assets)}",
                    *[f"asset={u}" for u in http_assets[:10]],
                ],
            ),
            remediation=(
                "Serve every embedded asset over HTTPS, including basemap tiles, "
                "WMS/WFS endpoints, and third-party scripts. If the upstream does "
                "not support HTTPS, proxy it through a TLS-terminating CDN."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


@register(
    id="WEB-005",
    title="Third-party script loaded without Subresource Integrity",
    description=(
        "A ``<script>`` element loaded from a different origin lacks the "
        "``integrity`` attribute. If the third-party (or its CDN) is "
        "compromised, the page silently executes attacker-controlled "
        "JavaScript with full access to the user's session and DOM."
    ),
    category="web",
    severity=Severity.LOW,
    cwe="CWE-353",
    cvss_vector="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",),
    target_kinds=("web_page",),
    tags=("web", "sri", "supply-chain"),
)
class MissingSriCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None:
            return
        offenders: list[str] = [
            script["src"]
            for script in result.scripts
            if script.get("src")
            and not _same_origin(result.final_url, script["src"])
            and not (script.get("integrity") or "").strip()
        ]
        if not offenders:
            return
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{result.final_url}` loads {len(offenders)} third-party "
                'script(s) without an ``integrity="sha384-…"`` attribute. '
                "If the upstream is compromised, the page silently executes "
                "the attacker's JavaScript."
            ),
            evidence=Evidence(
                matched=", ".join(offenders[:5]),
                notes=[
                    f"third_party_count={len(offenders)}",
                    *[f"src={u}" for u in offenders[:10]],
                ],
            ),
            remediation=(
                'Add ``integrity="sha384-…"`` and ``crossorigin="anonymous"`` '
                "to every third-party ``<script>``. Pin to a specific version of "
                "the upstream library and refresh the integrity hash whenever "
                "you bump the version."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


@register(
    id="WEB-006",
    title="Iframe-embedded map without sandbox attribute",
    description=(
        "The page embeds another origin via ``<iframe>`` without a "
        "``sandbox`` attribute, which means the embedded document can run "
        "arbitrary JavaScript, navigate the parent, and submit forms. Map "
        "embeds in particular often pull from operator-managed dashboards "
        "that warrant tighter isolation."
    ),
    category="web",
    severity=Severity.LOW,
    cwe="CWE-1021",
    cvss_vector="AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#sandbox",),
    target_kinds=("web_page",),
    tags=("web", "iframe", "sandbox"),
)
class IframeSandboxCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.WEB_PAGE:
            return
        result = cached_discovery(ctx)
        if result is None:
            return
        offenders: list[str] = [
            iframe["src"]
            for iframe in result.iframes
            if iframe.get("src") and not (iframe.get("sandbox") or "").strip()
        ]
        if not offenders:
            return
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{result.final_url}` embeds {len(offenders)} iframe(s) without "
                "a ``sandbox`` attribute. Each embedded document runs with full "
                "JavaScript privileges in the user's browser."
            ),
            evidence=Evidence(
                matched=", ".join(offenders[:5]),
                notes=[
                    f"iframe_count={len(offenders)}",
                    *[f"src={u}" for u in offenders[:10]],
                ],
            ),
            remediation=(
                'Add ``sandbox="allow-scripts allow-same-origin"`` (or a '
                "stricter combination) to every iframe whose contents you do "
                "not fully control. For map embeds where pop-out interaction "
                'is needed, prefer ``sandbox="allow-scripts allow-popups"``.'
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )
