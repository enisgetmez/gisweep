"""SARIF 2.1.0 writer.

Emits a single-run report whose tool driver carries the full check catalogue
as ``rules``. Each result is enriched with KVKK/GDPR/CWE properties so that
GitHub Code Scanning, Azure DevOps, and similar consumers can filter by
compliance dimension.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from gisweep import _version
from gisweep.core.finding import Severity
from gisweep.core.registry import all_meta

if TYPE_CHECKING:
    from pathlib import Path

    from gisweep.core.finding import Finding
    from gisweep.core.registry import CheckMeta
    from gisweep.core.runner import ScanMeta


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
)
TOOL_INFORMATION_URI = "https://github.com/enisgetmez/gisweep"
_EXIT_RUNTIME_ERROR = 2  # ScanMeta.exit_code == 2 means a runtime failure aborted the scan

_SEVERITY_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


class SarifWriter:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: list[Finding], meta: ScanMeta) -> None:
        used_ids = {f.check_id for f in findings}
        catalogue = [m for m in all_meta() if m.id in used_ids]
        rule_index = {meta_.id: idx for idx, meta_ in enumerate(catalogue)}

        document = {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gisweep",
                            "version": _version.__version__,
                            "informationUri": TOOL_INFORMATION_URI,
                            "rules": [_rule(meta_) for meta_ in catalogue],
                        }
                    },
                    "automationDetails": {"id": f"gisweep/{meta.scan_id}"},
                    "invocations": [
                        {
                            "executionSuccessful": meta.exit_code != _EXIT_RUNTIME_ERROR,
                            "exitCode": meta.exit_code,
                            "startTimeUtc": meta.started_at.isoformat(),
                            "endTimeUtc": meta.finished_at.isoformat(),
                            "commandLine": "gisweep",
                        }
                    ],
                    "results": [_result(f, rule_index) for f in findings],
                    "taxonomies": _taxonomies(),
                }
            ],
        }
        self._path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def _rule(meta: CheckMeta) -> dict[str, Any]:
    properties: dict[str, Any] = {"category": meta.category, "tags": ["security", meta.category]}
    if meta.kvkk:
        properties["kvkk"] = list(meta.kvkk)
    if meta.gdpr:
        properties["gdpr"] = list(meta.gdpr)
    if meta.cwe:
        properties["cwe"] = meta.cwe
    if meta.cvss_vector:
        properties["cvss"] = meta.cvss_vector
    rule: dict[str, Any] = {
        "id": meta.id,
        "name": _camel(meta.id),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description},
        "defaultConfiguration": {"level": _SEVERITY_LEVEL[meta.severity]},
        "properties": properties,
    }
    if meta.references:
        rule["helpUri"] = meta.references[0]
    return rule


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "severity": finding.severity.value,
        "compliance": {
            "kvkk": list(finding.kvkk_articles),
            "gdpr": list(finding.gdpr_articles),
        },
        "tags": list(finding.tags),
    }
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.cvss_score is not None:
        properties["cvssScore"] = finding.cvss_score

    result: dict[str, Any] = {
        "ruleId": finding.check_id,
        "level": _SEVERITY_LEVEL[finding.severity],
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.target.url},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": properties,
    }
    if finding.check_id in rule_index:
        result["ruleIndex"] = rule_index[finding.check_id]
    return result


def _taxonomies() -> list[dict[str, Any]]:
    return [
        {
            "name": "KVKK",
            "fullDescription": {
                "text": "KVKK — Kisisel Verilerin Korunmasi Kanunu (Turkish data protection law).",
            },
            "informationUri": "https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf",
        },
        {
            "name": "GDPR",
            "fullDescription": {"text": "EU General Data Protection Regulation 2016/679."},
            "informationUri": "https://gdpr-info.eu",
        },
    ]


def _camel(check_id: str) -> str:
    parts = check_id.replace("-", "_").split("_")
    return "".join(p.capitalize() for p in parts)
