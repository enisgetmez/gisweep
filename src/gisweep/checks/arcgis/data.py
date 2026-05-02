"""Data-exposure checks: ARC-013 (unbounded query) and ARC-014 (PII fields)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.checks.arcgis._helpers import (
    fetch_layer_info,
    has_anonymous_token,
)
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.registry import register
from gisweep.patterns.pii import get_pii_matcher

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context

_DEFAULT_RECORD_CAP_THRESHOLD = 5000


@register(
    id="ARC-013",
    title="Layer query has no effective record-count cap",
    description=(
        "The layer's advertised ``maxRecordCount`` is missing or large enough "
        "to permit dumping a substantial portion of the dataset in a single "
        "``query`` request. Combined with anonymous read access and PII "
        "fields, this lets an attacker exfiltrate the entire table with a "
        "few HTTP calls."
    ),
    category="arcgis",
    severity=Severity.HIGH,
    cwe="CWE-770",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
    kvkk=("m12",),
    gdpr=("art32",),
    references=(
        "https://developers.arcgis.com/rest/services-reference/query-feature-service-layer-.htm",
    ),
    target_kinds=("arcgis_layer",),
    tags=("data-exposure", "exfil"),
)
class UnboundedQueryCheck(Check):
    async def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        if target.kind != TargetKind.ARCGIS_LAYER:
            return
        try:
            info = await fetch_layer_info(ctx, target.url)
        except Exception as exc:
            ctx.logger.debug("arc013.fetch_failed", url=target.url, error=str(exc))
            return
        max_record_count = info.get("maxRecordCount")
        if (
            isinstance(max_record_count, int)
            and 0 < max_record_count <= _DEFAULT_RECORD_CAP_THRESHOLD
        ):
            return
        layer_name = str(info.get("name") or "")
        notes = [f"max_record_count={max_record_count!r}"]
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            target=target,
            description=(
                f"Layer `{layer_name}` at `{target.url}` reports "
                f"``maxRecordCount={max_record_count!r}``. A single query with "
                "``where=1=1&outFields=*`` can therefore exfiltrate a large slice of "
                "the dataset — particularly impactful when the layer holds personal data."
            ),
            evidence=Evidence(matched=f"maxRecordCount={max_record_count!r}", notes=notes),
            remediation=(
                "Set a conservative ``maxRecordCount`` (e.g. 1000) on the layer and "
                "enforce server-side query throttling. If the dataset is publishable in "
                "bulk, document the export pathway separately so that interactive queries "
                "do not become the data export channel."
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
    id="ARC-014",
    title="Layer exposes PII fields",
    description=(
        "Field names and aliases on the layer match well-known personal-data "
        "patterns (national ID, email, phone, address, IBAN, health, "
        "religion, etc.). When the layer is reachable without authentication "
        "this is a direct KVKK Madde 12 / GDPR Art. 32 issue; sensitive "
        "categories additionally engage KVKK Madde 6 / GDPR Art. 9."
    ),
    category="arcgis",
    severity=Severity.CRITICAL,
    cwe="CWE-200",
    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    kvkk=("m6", "m12"),
    gdpr=("art9", "art32"),
    references=(
        "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
        "https://gdpr-info.eu/art-9-gdpr/",
    ),
    target_kinds=("arcgis_layer",),
    tags=("pii", "data-exposure"),
)
class PiiFieldsExposedCheck(Check):
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
            ctx.logger.debug("arc014.fetch_failed", url=target.url, error=str(exc))
            return
        matcher = get_pii_matcher()
        kvkk: set[str] = set()
        gdpr: set[str] = set()
        sensitive_hits = False
        matched_fields: list[str] = []
        labels: list[str] = []

        for field_spec in info.get("fields") or []:
            name = str(field_spec.get("name") or "")
            alias = str(field_spec.get("alias") or "")
            for hit in matcher.match_field(name=name, alias=alias):
                matched_fields.append(name or alias)
                labels.append(hit.pattern.label)
                kvkk.update(hit.pattern.kvkk)
                gdpr.update(hit.pattern.gdpr)
                if hit.pattern.sensitive:
                    sensitive_hits = True

        if not matched_fields:
            return

        severity = Severity.CRITICAL if sensitive_hits else Severity.HIGH
        layer_name = str(info.get("name") or "")
        unique_labels = sorted(set(labels))
        unique_fields = sorted(set(matched_fields))
        yield Finding(
            check_id=self.meta.id,
            title=self.meta.title,
            severity=severity,
            target=target,
            description=(
                f"Layer `{layer_name}` at `{target.url}` exposes "
                f"{len(unique_fields)} field(s) matching personal-data patterns "
                f"({', '.join(unique_labels)}). Combined with anonymous read access "
                "this leaks personal data without legal basis or technical safeguards."
            ),
            evidence=Evidence(
                matched=", ".join(unique_fields),
                notes=[
                    f"fields={','.join(unique_fields)}",
                    f"categories={','.join(unique_labels)}",
                    f"sensitive={sensitive_hits}",
                ],
            ),
            remediation=(
                "Restrict the layer to authenticated, role-scoped users; remove or "
                "pseudonymize fields that are not strictly required for the public "
                "use-case. Where legitimate publication is needed (e.g. official "
                "registries), confirm the legal basis and document it in your KVKK "
                "VERBİS / GDPR Article 30 record."
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
