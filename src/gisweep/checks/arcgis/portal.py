"""ARC-016 — Portal items shared publicly carry sensitive metadata.

ArcGIS Portal / Online's ``/sharing/rest/search`` endpoint enumerates
items with their ``access`` field set to ``private``, ``shared``, ``org``,
or ``public``. Items shared as ``public`` can be discovered by any
unauthenticated caller and consumed via the corresponding service URL.

The check:
1. Runs only when the target URL is a Portal sharing root (i.e. contains
   ``/sharing/rest`` or the runtime supplied a ``--portal-url``).
2. Calls ``/sharing/rest/search?q=access:public&num=100&f=json`` to pull
   the first page of public items (up to 100 — pagination not required
   for the audit signal).
3. For each item, runs the bundled PII pattern matcher across its title,
   description, snippet, and tags. A hit means the item is shared
   publicly *and* its metadata advertises personal data — usually a
   misconfiguration.
4. Emits one Finding per matching item, severity HIGH (CRITICAL when the
   PII pattern is in a sensitive category like health/religion).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.patterns.pii import get_pii_matcher

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


_PORTAL_MARKERS: tuple[str, ...] = ("/sharing/rest",)
_DEFAULT_PAGE_SIZE = 100
_HTTP_OK = 200
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9_üöçğışÜÖÇĞİŞ]+")


def _portal_root(target_url: str) -> str | None:
    """Extract the portal root from a TargetRef URL or runtime config."""
    for marker in _PORTAL_MARKERS:
        if marker in target_url:
            return target_url.split(marker, 1)[0] + marker
    return None


@register(
    id="ARC-016",
    title="Portal item shared publicly carries personal-data metadata",
    description=(
        "ArcGIS Online / Enterprise Portal items shared with ``access: "
        "public`` are discoverable and downloadable by anyone. When the "
        "item title, description, snippet, or tags match well-known "
        "personal-data patterns, the deployment is most likely sharing "
        "the wrong dataset publicly."
    ),
    category="arcgis",
    severity=Severity.HIGH,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://developers.arcgis.com/rest/users-groups-and-items/search.htm",),
    target_kinds=("arcgis_root",),
    tags=("portal", "acl", "public-share"),
)
class PortalItemAclCheck(Check):
    async def run(  # noqa: PLR0911, PLR0912 -- guard cascade is the simplest expression
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return
        portal = _portal_root(target.url)
        if portal is None:
            # Fall back to the configured portal_url from --portal-url, if any.
            auth = ctx.options.auth
            if auth is None or not auth.portal_url:
                return
            portal = auth.portal_url.rstrip("/") + "/sharing/rest"
        search_url = f"{portal.rstrip('/')}/search"
        params: dict[str, Any] = {
            "q": "access:public",
            "num": str(_DEFAULT_PAGE_SIZE),
            "f": "json",
        }

        try:
            response = await ctx.http.get(search_url, params=params)
        except (httpx.HTTPError, OSError) as exc:
            ctx.logger.debug("arc016.search_failed", url=search_url, error=str(exc))
            return
        if response.status_code != _HTTP_OK or not response.content:
            return
        try:
            payload = response.json()
        except ValueError:
            return
        if not isinstance(payload, dict):
            return

        results = payload.get("results")
        if not isinstance(results, list):
            return

        matcher = get_pii_matcher()
        for item in results:
            if not isinstance(item, dict):
                continue
            access = str(item.get("access") or "")
            if access != "public":
                continue
            title = str(item.get("title") or "")
            snippet = str(item.get("snippet") or "")
            description = str(item.get("description") or "")
            tags = item.get("tags") or []
            tag_blob = ", ".join(str(t) for t in tags if t)
            full_blob = f"{title}\n{snippet}\n{description}\n{tag_blob}"

            # Free-form metadata: split into individual words so the PII regex
            # word boundaries can fire. Field-name matching alone misses
            # patterns embedded inside multi-word titles like "Citizen TCKN
            # registry".
            words = [w for w in _WORD_SPLIT_RE.split(full_blob) if w]
            hits = []
            for word in words:
                hits.extend(matcher.match_field(name=word, alias=""))
            if not hits:
                continue

            sensitive = any(hit.pattern.sensitive for hit in hits)
            severity = Severity.CRITICAL if sensitive else Severity.HIGH
            kvkk: set[str] = set()
            gdpr: set[str] = set()
            categories: set[str] = set()
            for hit in hits:
                kvkk.update(hit.pattern.kvkk)
                gdpr.update(hit.pattern.gdpr)
                categories.add(hit.pattern.label)
            item_id = str(item.get("id") or "")
            item_url = str(item.get("url") or "")
            type_str = str(item.get("type") or "")

            yield Finding(
                check_id=self.meta.id,
                title=self.meta.title,
                severity=severity,
                target=TargetRef(
                    url=item_url or f"{portal}/content/items/{item_id}",
                    kind=TargetKind.ARCGIS_ROOT,
                ),
                description=(
                    f"Portal item `{title}` (id `{item_id}`, type `{type_str}`) is "
                    "shared with ``access: public`` and its metadata matches the "
                    f"following personal-data patterns: {', '.join(sorted(categories))}. "
                    "Either the share level is wrong or the item should not be "
                    "exposed to anonymous users."
                ),
                evidence=Evidence(
                    matched=", ".join(sorted(categories)),
                    notes=[
                        f"item_id={item_id}",
                        f"item_type={type_str}",
                        f"access={access}",
                        f"item_url={item_url}",
                        f"snippet={snippet[:120]}",
                        f"matched_blob={full_blob[:200]}",
                    ],
                ),
                remediation=(
                    "In Portal Manager / ArcGIS Online, change the item's share "
                    "level from ``Public`` to ``Organization`` or a specific "
                    "group. Audit who downloaded the item while it was public "
                    "and notify affected data subjects if KVKK / GDPR breach "
                    "thresholds are met."
                ),
                references=list(self.meta.references),
                cwe=self.meta.cwe,
                cvss_vector=self.meta.cvss_vector,
                kvkk_articles=sorted(kvkk),
                gdpr_articles=sorted(gdpr),
                tags=list(self.meta.tags),
                discovered_at=datetime.now(tz=UTC),
                scan_id=ctx.scan_id,
            )
