"""Cross-cutting compliance rules.

Per-check ``Finding`` instances already carry KVKK/GDPR article references via
``@register`` metadata. The overlay layered on top of them is responsible for
the *aggregate* obligations — situations where a single finding alone does
not constitute a violation but a combination does. The output is a list of
``COMP-*`` findings appended to the original list; original findings are not
mutated.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef

if TYPE_CHECKING:
    from collections.abc import Iterable

    pass

_PII_THRESHOLD_FOR_AGGREGATE = 5


def apply_overlay(findings: Iterable[Finding], *, scan_id: str) -> list[Finding]:
    """Return ``list(findings) + [aggregate findings]``."""
    materialised = list(findings)
    extras: list[Finding] = []
    extras.extend(_comp_001_pii_aggregate(materialised, scan_id))
    extras.extend(_comp_003_admin_plus_data(materialised, scan_id))
    return materialised + extras


def _comp_001_pii_aggregate(findings: list[Finding], scan_id: str) -> list[Finding]:
    """KVKK Madde 12 aggregate: ≥5 PII-bearing layers exposed anonymously."""
    pii_findings = [f for f in findings if f.check_id == "ARC-014"]
    if len(pii_findings) < _PII_THRESHOLD_FOR_AGGREGATE:
        return []
    matched_layers = sorted({f.target.url for f in pii_findings})
    notes = [f"pii_finding_count={len(pii_findings)}"]
    notes.extend(f"layer={url}" for url in matched_layers[:10])
    if len(matched_layers) > 10:  # noqa: PLR2004 -- presentation cap, not a domain constraint
        notes.append(f"…and {len(matched_layers) - 10} more")
    return [
        Finding(
            check_id="COMP-001",
            title="KVKK Madde 12 aggregate — ≥5 PII-bearing layers exposed anonymously",
            severity=Severity.CRITICAL,
            target=_first_target(pii_findings),
            description=(
                f"{len(pii_findings)} ARC-014 findings on this scan indicate "
                f"{len(matched_layers)} distinct layers expose personal data "
                "without authentication. Under KVKK Madde 12 the controller is "
                "obliged to take all necessary technical and organizational "
                "measures to provide an appropriate level of security; the same "
                "obligation maps to GDPR Art. 32 (security of processing)."
            ),
            evidence=Evidence(
                matched=f"{len(matched_layers)} layers",
                notes=notes,
            ),
            remediation=(
                "Audit each affected layer (see ARC-014 findings), restrict "
                "anonymous read access on those that hold personal data, and "
                "document the lawful basis + retention for layers that must "
                "stay public."
            ),
            references=[
                "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
                "https://gdpr-info.eu/art-32-gdpr/",
            ],
            cwe="CWE-200",
            kvkk_articles=["m12"],
            gdpr_articles=["art32"],
            tags=["compliance", "aggregate", "kvkk-m12"],
            discovered_at=datetime.now(tz=UTC),
            scan_id=scan_id,
        )
    ]


def _comp_003_admin_plus_data(findings: list[Finding], scan_id: str) -> list[Finding]:
    """GDPR Art. 32 technical-measures gap: admin endpoint exposed AND data
    services unauthenticated."""
    admin_findings = [f for f in findings if f.check_id == "ARC-003"]
    data_findings = [
        f for f in findings if f.check_id in {"ARC-001", "ARC-002", "ARC-014", "OGC-005"}
    ]
    if not admin_findings or not data_findings:
        return []
    admin_urls = sorted({f.target.url for f in admin_findings})
    data_check_ids = sorted({f.check_id for f in data_findings})
    return [
        Finding(
            check_id="COMP-003",
            title="GDPR Art. 32 technical-measures gap — admin exposed AND data unauthenticated",
            severity=Severity.CRITICAL,
            target=admin_findings[0].target,
            description=(
                "An ArcGIS administrator directory is reachable from the public "
                "internet at the same time that one or more data services are "
                "anonymously accessible. Combined, the deployment fails to meet "
                "GDPR Art. 32 (technical and organizational measures appropriate "
                "to the risk) and KVKK Madde 12 (data security obligations)."
            ),
            evidence=Evidence(
                matched=", ".join(admin_urls),
                notes=[
                    f"admin_endpoints={','.join(admin_urls)}",
                    f"co_occurring_checks={','.join(data_check_ids)}",
                ],
            ),
            remediation=(
                "Move the admin directory behind a VPN / IP allow-list AND "
                "require authentication on every layer/service that handles "
                "personal or operational data. The two controls reinforce each "
                "other; neither alone is sufficient."
            ),
            references=[
                "https://gdpr-info.eu/art-32-gdpr/",
                "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
            ],
            cwe="CWE-284",
            kvkk_articles=["m12"],
            gdpr_articles=["art32"],
            tags=["compliance", "aggregate", "gdpr-art32"],
            discovered_at=datetime.now(tz=UTC),
            scan_id=scan_id,
        )
    ]


def _first_target(findings: list[Finding]) -> TargetRef:
    if findings:
        return findings[0].target
    return TargetRef(url="", kind=TargetKind.UNKNOWN)
