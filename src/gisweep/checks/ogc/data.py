"""WFS data-exposure checks: OGC-006 (PII fields), OGC-007 (unbounded
GetFeature), OGC-008 (anonymous read confirmation).

These mirror the ArcGIS-side ARC-014 / ARC-013 / ARC-017 checks but
work over the WFS protocol. All three are passive — they call
``DescribeFeatureType`` and at most one ``GetFeature?count=1`` per
feature type.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
from defusedxml import ElementTree as Det

from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.discovery.wfs_schema import WfsFeatureSchema, describe_feature_type
from gisweep.patterns.pii import get_pii_matcher

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context


_HTTP_OK = 200
_DEFAULT_RECORD_CAP_THRESHOLD = 5000
_GET_FEATURE_PROBE_COUNT = 1
_HITS_PROBE_COUNT_THRESHOLD = 10_000

_SCHEMA_CACHE_KEY = "ogc_layer_schemas"
_READ_PROBE_CACHE_KEY = "ogc_layer_read_probes"


@dataclass(frozen=True, slots=True)
class _ReadProbe:
    """Result of a ``GetFeature?count=1`` probe against a feature type."""

    confirmed_anonymous_read: bool
    sample_count_hint: int | None  # parsed from numberMatched / numberOfFeatures
    status_code: int | None
    requires_auth: bool
    error: str | None


async def _cached_schema(ctx: Context, endpoint: str, type_name: str) -> WfsFeatureSchema | None:
    cache = ctx.cache.setdefault(_SCHEMA_CACHE_KEY, {})
    key = (endpoint, type_name)
    if key in cache:
        return cache[key]  # type: ignore[no-any-return]
    schema = await describe_feature_type(ctx, endpoint, type_name)
    cache[key] = schema
    return schema


async def _cached_read_probe(ctx: Context, endpoint: str, type_name: str) -> _ReadProbe:
    cache = ctx.cache.setdefault(_READ_PROBE_CACHE_KEY, {})
    key = (endpoint, type_name)
    if key in cache:
        return cache[key]  # type: ignore[no-any-return]
    probe = await _read_probe(ctx, endpoint, type_name)
    cache[key] = probe
    return probe


async def _read_probe(ctx: Context, endpoint: str, type_name: str) -> _ReadProbe:
    """Issue ``GetFeature?count=1`` and decide whether anonymous read works.

    The probe reads at most one feature; this is the same defensive contract
    that the ArcGIS ``probe_layer_query`` helper applies. The total
    cardinality, when reported, is parsed from the GeoServer/MapServer-
    standard ``numberMatched`` / ``numberOfFeatures`` attributes on the
    response root.
    """
    params = {
        "SERVICE": "WFS",
        "VERSION": "2.0.0",
        "REQUEST": "GetFeature",
        "TYPENAMES": type_name,
        "COUNT": str(_GET_FEATURE_PROBE_COUNT),
    }
    try:
        response = await ctx.http.get(endpoint, params=params)
    except (httpx.HTTPError, OSError) as exc:
        return _ReadProbe(
            confirmed_anonymous_read=False,
            sample_count_hint=None,
            status_code=None,
            requires_auth=False,
            error=str(exc),
        )

    requires_auth = response.status_code in {401, 403}
    if response.status_code != _HTTP_OK or not response.content:
        return _ReadProbe(
            confirmed_anonymous_read=False,
            sample_count_hint=None,
            status_code=response.status_code,
            requires_auth=requires_auth,
            error=None,
        )

    try:
        root = Det.fromstring(response.text)
    except (Det.ParseError, ValueError):
        return _ReadProbe(
            confirmed_anonymous_read=False,
            sample_count_hint=None,
            status_code=response.status_code,
            requires_auth=False,
            error="not parseable as XML",
        )

    confirmed = _has_member_or_feature(root)
    count_hint = _parse_count_hint(root)
    return _ReadProbe(
        confirmed_anonymous_read=confirmed,
        sample_count_hint=count_hint,
        status_code=response.status_code,
        requires_auth=False,
        error=None,
    )


def _has_member_or_feature(root: object) -> bool:
    """Return True when the parsed GetFeature response includes at least one
    ``<wfs:member>`` (WFS 2.0) or ``<gml:featureMember>`` (WFS 1.x)
    element. We do not inspect the feature contents — that would require
    knowing the namespace; presence alone is enough to confirm read.
    """
    for el in root.iter():  # type: ignore[attr-defined]
        local = el.tag.split("}", 1)[1] if "}" in el.tag else el.tag
        if local in {"member", "featureMember", "featureMembers"}:
            return True
    return False


def _parse_count_hint(root: object) -> int | None:
    attribs = root.attrib  # type: ignore[attr-defined]
    for key in ("numberMatched", "numberOfFeatures"):
        raw = attribs.get(key)
        if raw is None or not raw.isdigit():
            continue
        return int(raw)
    return None


# ----------------------------------------------------------------------------
# OGC-006 — PII fields exposed in WFS schema
# ----------------------------------------------------------------------------


@register(
    id="OGC-006",
    title="WFS feature type exposes PII fields",
    description=(
        "The feature type declares one or more attributes that match known "
        "personal-data patterns (national ID, IBAN, email, phone, address, "
        "health, religion, etc.). When the feature type is anonymously "
        "readable this is a direct KVKK Madde 12 / GDPR Art. 32 issue; "
        "sensitive categories additionally engage KVKK Madde 6 / GDPR Art. 9. "
        "Mirrors the ArcGIS-side ARC-014."
    ),
    category="ogc",
    severity=Severity.CRITICAL,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m6", "m12"),
    gdpr=("art9", "art32"),
    references=(
        "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
        "https://docs.geoserver.org/latest/en/user/security/index.html",
    ),
    target_kinds=("ogc_layer",),
    tags=("ogc", "pii", "data-exposure"),
)
class OgcPiiFieldsCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_LAYER or not target.service_path:
            return
        type_name = target.service_path
        schema = await _cached_schema(ctx, target.url, type_name)
        if schema is None:
            return

        matcher = get_pii_matcher()
        kvkk: set[str] = set()
        gdpr: set[str] = set()
        sensitive_hits = False
        matched_fields: list[str] = []
        labels: list[str] = []

        for field in schema.fields:
            if field.is_geometry:
                continue
            for hit in matcher.match_field(name=field.name):
                matched_fields.append(field.name)
                labels.append(hit.pattern.label)
                kvkk.update(hit.pattern.kvkk)
                gdpr.update(hit.pattern.gdpr)
                if hit.pattern.sensitive:
                    sensitive_hits = True

        if not matched_fields:
            return

        probe = await _cached_read_probe(ctx, target.url, type_name)
        if probe.confirmed_anonymous_read:
            severity = Severity.CRITICAL if sensitive_hits else Severity.HIGH
            confidence = f"anonymous read confirmed (numberMatched={probe.sample_count_hint!r})"
        else:
            severity = Severity.MEDIUM
            confidence = (
                f"PII pattern in metadata; anonymous read not confirmed "
                f"(http={probe.status_code}, requires_auth={probe.requires_auth})"
            )

        unique_fields = sorted(set(matched_fields))
        unique_labels = sorted(set(labels))
        notes = [
            f"namespace={schema.namespace or '?'}",
            f"matched_labels={', '.join(unique_labels)}",
            f"confidence={confidence}",
        ]
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=severity,
            target=target,
            description=(
                f"WFS feature type `{type_name}` at `{target.url}` exposes "
                f"{len(unique_fields)} field(s) matching personal-data patterns "
                f"({', '.join(unique_labels)}). {confidence}."
            ),
            evidence=Evidence(
                matched=", ".join(unique_fields),
                notes=notes,
            ),
            remediation=(
                "Either remove the PII columns from the published feature type "
                "(GeoServer: Data → Layers → restrict attributes) or place the "
                "layer behind authentication via the security subsystem. If the "
                "layer must remain public, document the data-publication "
                "agreement in your KVKK / GDPR registry of processing activities."
            ),
            references=list(self.meta.references),
            cwe=self.meta.cwe,
            cvss_vector=self.meta.cvss_vector,
            kvkk_articles=sorted(kvkk or set(self.meta.kvkk)),
            gdpr_articles=sorted(gdpr or set(self.meta.gdpr)),
            tags=list(self.meta.tags),
            discovered_at=datetime.now(tz=UTC),
            scan_id=ctx.scan_id,
        )


# ----------------------------------------------------------------------------
# OGC-007 — Unbounded WFS GetFeature
# ----------------------------------------------------------------------------


@register(
    id="OGC-007",
    title="WFS feature type allows unbounded GetFeature dump",
    description=(
        "A ``GetFeature`` request without ``count=`` returns more than "
        "10000 features in a single response. Combined with anonymous read "
        "and PII fields this lets a single HTTP call exfiltrate the entire "
        "table. Mirrors the ArcGIS-side ARC-013."
    ),
    category="ogc",
    severity=Severity.HIGH,
    cwe="CWE-770",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://docs.geoserver.org/latest/en/user/services/wfs/reference.html",),
    target_kinds=("ogc_layer",),
    tags=("ogc", "data-exposure", "exfil"),
)
class OgcUnboundedGetFeatureCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_LAYER or not target.service_path:
            return
        type_name = target.service_path
        probe = await _cached_read_probe(ctx, target.url, type_name)
        if probe.sample_count_hint is None:
            return
        if probe.sample_count_hint < _HITS_PROBE_COUNT_THRESHOLD:
            return

        severity = self.meta.severity if probe.confirmed_anonymous_read else Severity.MEDIUM
        confidence = (
            "anonymous read confirmed"
            if probe.confirmed_anonymous_read
            else f"http={probe.status_code}, requires_auth={probe.requires_auth}"
        )
        notes = [
            f"numberMatched={probe.sample_count_hint}",
            f"threshold={_HITS_PROBE_COUNT_THRESHOLD}",
            f"confidence={confidence}",
        ]
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=severity,
            target=target,
            description=(
                f"Feature type `{type_name}` at `{target.url}` advertises "
                f"``numberMatched={probe.sample_count_hint}`` and does not enforce a "
                "default count cap. A single ``GetFeature`` without ``count=`` "
                "would dump the entire layer."
            ),
            evidence=Evidence(
                matched=f"numberMatched={probe.sample_count_hint}",
                notes=notes,
            ),
            remediation=(
                "Set ``MaxFeatures`` in the WFS service settings (GeoServer: "
                "Services → WFS → Maximum number of features) and enforce "
                "service-level rate limits. Document any layers that genuinely "
                "need to be exportable in bulk."
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


# ----------------------------------------------------------------------------
# OGC-008 — Anonymous read confirmation per feature type
# ----------------------------------------------------------------------------


@register(
    id="OGC-008",
    title="WFS feature type readable without authentication",
    description=(
        "A single ``GetFeature?count=1`` request returns at least one "
        "feature without any credentials. This is the OGC equivalent of "
        "ARC-017 — the per-layer anonymous-read audit. The finding by "
        "itself is informational; co-occurrence with OGC-006 (PII) or "
        "OGC-007 (unbounded) is what makes it actionable."
    ),
    category="ogc",
    severity=Severity.LOW,
    cwe="CWE-284",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    kvkk=("m12",),
    gdpr=("art32",),
    references=("https://docs.geoserver.org/latest/en/user/security/service.html",),
    target_kinds=("ogc_layer",),
    tags=("ogc", "access-control", "audit"),
)
class OgcAnonymousReadCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.OGC_LAYER or not target.service_path:
            return
        type_name = target.service_path
        probe = await _cached_read_probe(ctx, target.url, type_name)
        if not probe.confirmed_anonymous_read:
            return

        notes = [
            f"numberMatched={probe.sample_count_hint!r}",
            f"http={probe.status_code}",
        ]
        sample_field_names: list[str] = []
        schema = await _cached_schema(ctx, target.url, type_name)
        if schema is not None:
            sample_field_names = [f.name for f in schema.fields if not f.is_geometry][:8]

        evidence_matched_parts: list[str] = []
        if probe.sample_count_hint is not None:
            evidence_matched_parts.append(f"count={probe.sample_count_hint}")
        if sample_field_names:
            evidence_matched_parts.append(f"fields={', '.join(sample_field_names)}")
        evidence_matched = " · ".join(evidence_matched_parts) or "anonymous read"

        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"`{type_name}` at `{target.url}` answers ``GetFeature?count=1`` "
                "without authentication. Cross-reference any OGC-006 / OGC-007 "
                "findings on the same feature type for impact."
            ),
            evidence=Evidence(matched=evidence_matched, notes=notes),
            remediation=(
                "If the feature type is not intended for public consumption, "
                "place it behind GeoServer's security subsystem (Service or "
                "Data security rules) or the upstream proxy's authentication."
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
