"""WEB-002 — secret leakage in the page's HTML, scripts, and XHR responses."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.web._helpers import cached_discovery
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.patterns.secrets import get_secret_matcher, redact_secret

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


@register(
    id="WEB-002",
    title="API key or token leaked in browser-loaded source",
    description=(
        "One or more network responses fetched by the page contain a value "
        "matching a known secret pattern (Google Maps, Mapbox, AWS, GitHub, "
        "Stripe, JWT, ArcGIS ?token=…). Anything served to the browser is "
        "public; the credential must be rotated immediately."
    ),
    category="web",
    severity=Severity.HIGH,
    cwe="CWE-798",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(),
    target_kinds=("web_page",),
    tags=("web", "secret-leak"),
)
class WebSecretLeakageCheck(Check):
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
        matcher = get_secret_matcher()
        seen: set[tuple[str, str]] = set()
        bodies: list[tuple[str, str]] = [(result.final_url, result.page_html)]
        bodies.extend((b.url, b.body) for b in result.bodies)
        for source, body in bodies:
            if not body:
                continue
            for match in matcher.scan(body):
                key = (match.pattern.id, match.matched)
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    check_id=self.meta.id,
                    title=f"{match.pattern.label} leaked in browser-loaded source",
                    severity=match.pattern.severity,
                    target=TargetRef(url=source, kind=TargetKind.ASSET),
                    description=(
                        f"`{source}` (loaded by `{result.final_url}`) contains a value "
                        f"matching the {match.pattern.label} pattern. The browser sees "
                        "this verbatim, so the credential should be considered public."
                    ),
                    evidence=Evidence(
                        matched=redact_secret(match.matched),
                        notes=[
                            f"pattern_id={match.pattern.id}",
                            f"page_url={result.final_url}",
                            f"resource_url={source}",
                            f"offset={match.start}-{match.end}",
                        ],
                    ),
                    remediation=(
                        "Revoke the leaked credential at its issuer, rotate dependent "
                        "systems, and move the secret to a server-side proxy or "
                        "environment-restricted key (e.g. Google Maps HTTP-referrer "
                        "restriction, Mapbox URL allowlist)."
                    ),
                    references=list(self.meta.references),
                    cwe=self.meta.cwe,
                    kvkk_articles=list(match.pattern.kvkk),
                    gdpr_articles=list(match.pattern.gdpr),
                    tags=[*list(self.meta.tags), match.pattern.id],
                    discovered_at=datetime.now(tz=UTC),
                    scan_id=ctx.scan_id,
                )
