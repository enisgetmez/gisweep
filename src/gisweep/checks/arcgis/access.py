"""ARC-017 / ARC-018 — read-permission verification + REST inventory rollup."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.arcgis._helpers import (
    LayerAccessProbe,
    fetch_layer_info,
    has_anonymous_token,
    probe_layer_query,
)
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.patterns.pii import get_pii_matcher

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


@register(
    id="ARC-017",
    title="ArcGIS layer is anonymously readable",
    description=(
        "An anonymous ``query?where=1=1&returnCountOnly=true`` request returned "
        "a row count, confirming that the layer's data is exposed without "
        "authentication. This is informational on its own but elevates the "
        "severity of co-occurring ARC-013 / ARC-014 findings on the same layer."
    ),
    category="arcgis",
    severity=Severity.INFO,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://developers.arcgis.com/rest/services-reference/query-feature-service-layer-.htm",
    ),
    target_kinds=("arcgis_layer",),
    tags=("anonymous", "read", "confirmation"),
)
class AnonymousReadConfirmedCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_LAYER:
            return
        if not has_anonymous_token(ctx):
            return
        probe = await probe_layer_query(ctx, target.url)
        if not probe.confirmed_anonymous_read:
            return
        try:
            info = await fetch_layer_info(ctx, target.url)
        except Exception as exc:
            ctx.logger.debug("arc017.fetch_failed", url=target.url, error=str(exc))
            return
        layer_name = str(info.get("name") or "")
        notes = [
            f"feature_count={probe.count}",
            f"http_status={probe.status_code}",
        ]
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"Layer `{layer_name}` at `{target.url}` returned a feature count of "
                f"{probe.count} for an anonymous count-only query. The data plane is "
                "reachable without authentication — confirm this is intentional."
            ),
            evidence=Evidence(matched=f"count={probe.count}", notes=notes),
            remediation=(
                "If the layer is meant to be public, document the lawful basis and "
                "ensure no PII / sensitive fields are exposed (see ARC-014). Otherwise "
                "restrict the layer to authenticated users via ArcGIS Server Manager → "
                "Security → Service-level access rules."
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
    id="ARC-018",
    title="ArcGIS REST inventory rollup",
    description=(
        "Aggregates the per-layer probe results into a single audit summary: "
        "how many folders, services, and layers were enumerated, how many "
        "responded to anonymous queries, and how many of those carry "
        "PII-pattern field names. The body is informational — every individual "
        "issue is also reported by its dedicated ARC-* check — but the summary "
        "gives the operator a one-line answer to 'what does this server "
        "actually expose?'."
    ),
    category="arcgis",
    severity=Severity.INFO,
    cwe="CWE-200",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(),
    target_kinds=("arcgis_root",),
    tags=("inventory", "summary"),
)
class ArcGISInventoryRollupCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_ROOT:
            return

        layer_probes: list[LayerAccessProbe] = [
            value
            for key, value in ctx.cache.items()
            if key.startswith("arcgis_layer_probe:") and isinstance(value, LayerAccessProbe)
        ]
        layer_infos: dict[str, dict[str, object]] = {
            key.split("arcgis_layer_info:", 1)[1]: value
            for key, value in ctx.cache.items()
            if key.startswith("arcgis_layer_info:") and isinstance(value, dict)
        }
        if not layer_probes and not layer_infos:
            return

        total_layers = len(layer_probes) or len(layer_infos)
        anon_readable = sum(1 for p in layer_probes if p.confirmed_anonymous_read)
        require_auth = sum(1 for p in layer_probes if p.requires_auth)
        pii_layers, pii_anon = _count_pii_layers(layer_infos, layer_probes)

        notes = [
            f"total_layers={total_layers}",
            f"anonymous_readable={anon_readable}",
            f"requires_auth={require_auth}",
            f"pii_pattern_layers={pii_layers}",
            f"pii_pattern_and_anonymous_read={pii_anon}",
        ]

        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"ArcGIS REST root at `{target.url}` enumerated {total_layers} layer(s); "
                f"{anon_readable} responded to anonymous queries and {require_auth} required "
                f"authentication. {pii_layers} layer(s) carry PII-pattern field names; "
                f"{pii_anon} of those are also anonymously readable — those are the "
                "highest-priority items in this report."
            ),
            evidence=Evidence(
                matched=f"{anon_readable}/{total_layers} anonymous-readable",
                notes=notes,
            ),
            remediation=(
                "Use this rollup as a triage map: anything appearing in both the "
                "anonymous-readable and PII columns warrants immediate attention. "
                "Cross-reference the per-layer ARC-013 / ARC-014 / ARC-017 findings "
                "for specifics."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            kvkk_articles=list(self.meta.kvkk),
            gdpr_articles=list(self.meta.gdpr),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


def _count_pii_layers(
    layer_infos: dict[str, dict[str, object]],
    layer_probes: list[LayerAccessProbe],
) -> tuple[int, int]:
    matcher = get_pii_matcher()
    pii_total = 0
    pii_anon = 0
    probe_by_url = {p.layer_url: p for p in layer_probes}
    for layer_url, info in layer_infos.items():
        fields = info.get("fields") or []
        if not isinstance(fields, list):
            continue
        for field_spec in fields:
            if not isinstance(field_spec, dict):
                continue
            name = str(field_spec.get("name") or "")
            alias = str(field_spec.get("alias") or "")
            if matcher.match_field(name=name, alias=alias):
                pii_total += 1
                probe = probe_by_url.get(layer_url)
                if probe is not None and probe.confirmed_anonymous_read:
                    pii_anon += 1
                break
    return pii_total, pii_anon
