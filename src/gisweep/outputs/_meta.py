"""Internal helpers shared by the file-emitting writers."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from gisweep.core.finding import Severity

if TYPE_CHECKING:
    from gisweep.core.runner import ScanMeta


def meta_to_dict(meta: ScanMeta) -> dict[str, Any]:
    return {
        "scan_id": meta.scan_id,
        "started_at": meta.started_at.isoformat(),
        "finished_at": meta.finished_at.isoformat(),
        "duration_seconds": (meta.finished_at - meta.started_at).total_seconds(),
        "targets": list(meta.targets),
        "gisweep_version": meta.gisweep_version,
        "exit_code": meta.exit_code,
        "counts_by_severity": {sev.value: meta.counts_by_severity.get(sev, 0) for sev in Severity},
    }


def compliance_matrix(findings: list[Any]) -> dict[str, dict[str, list[str]]]:
    """Build {kvkk:{article:[check_ids]}, gdpr:{...}}."""
    kvkk: dict[str, list[str]] = {}
    gdpr: dict[str, list[str]] = {}
    for f in findings:
        for art in f.kvkk_articles:
            kvkk.setdefault(art, []).append(f.check_id)
        for art in f.gdpr_articles:
            gdpr.setdefault(art, []).append(f.check_id)
    return {
        "kvkk": {k: sorted(set(v)) for k, v in sorted(kvkk.items())},
        "gdpr": {k: sorted(set(v)) for k, v in sorted(gdpr.items())},
    }


def severity_counts(findings: list[Any]) -> Counter[Severity]:
    return Counter(f.severity for f in findings)
