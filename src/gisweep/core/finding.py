"""Canonical data shapes for findings, targets, and evidence.

Pydantic models are used (instead of plain dataclasses) so that every output
writer gets validation and JSON serialization for free, including a stable
JSON-Schema export for the SARIF and JSON report formats.
"""

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

_FROZEN: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return _SEVERITY_LEVEL[self]

    def at_least(self, threshold: "Severity") -> bool:
        return self.level >= threshold.level


_SEVERITY_LEVEL: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TargetKind(StrEnum):
    ARCGIS_ROOT = "arcgis_root"
    ARCGIS_SERVICE = "arcgis_service"
    ARCGIS_LAYER = "arcgis_layer"
    OGC_SERVICE = "ogc_service"
    OGC_LAYER = "ogc_layer"
    WEB_PAGE = "web_page"
    ASSET = "asset"
    UNKNOWN = "unknown"


class TargetRef(BaseModel):
    model_config = _FROZEN

    url: str
    kind: TargetKind
    service_path: str | None = None
    layer_id: int | None = None


class HttpRequestSummary(BaseModel):
    model_config = _FROZEN

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str | None = None


class HttpResponseSummary(BaseModel):
    model_config = _FROZEN

    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str | None = None


class Evidence(BaseModel):
    model_config = _FROZEN

    request: HttpRequestSummary | None = None
    response: HttpResponseSummary | None = None
    matched: str | None = None
    screenshot_path: str | None = None
    notes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = _FROZEN

    check_id: str
    title: str
    severity: Severity
    target: TargetRef
    description: str
    evidence: Evidence
    remediation: str
    references: list[str] = Field(default_factory=list)
    cwe: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    kvkk_articles: list[str] = Field(default_factory=list)
    gdpr_articles: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime
    scan_id: str
