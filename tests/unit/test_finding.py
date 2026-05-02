"""Unit tests for the canonical data shapes."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from gisweep.core.finding import (
    Evidence,
    Finding,
    HttpRequestSummary,
    HttpResponseSummary,
    Severity,
    TargetKind,
    TargetRef,
)


class TestSeverity:
    def test_string_value(self) -> None:
        assert Severity.HIGH.value == "high"
        assert str(Severity.HIGH) == "Severity.HIGH" or "high" in str(Severity.HIGH)

    def test_levels_are_monotonic(self) -> None:
        levels = [s.level for s in Severity]
        assert levels == sorted(levels)
        assert len(set(levels)) == len(Severity)

    @pytest.mark.parametrize(
        ("value", "threshold", "expected"),
        [
            (Severity.CRITICAL, Severity.HIGH, True),
            (Severity.HIGH, Severity.HIGH, True),
            (Severity.MEDIUM, Severity.HIGH, False),
            (Severity.INFO, Severity.INFO, True),
            (Severity.INFO, Severity.LOW, False),
        ],
    )
    def test_at_least(self, value: Severity, threshold: Severity, expected: bool) -> None:
        assert value.at_least(threshold) is expected


class TestTargetRef:
    def test_minimal(self) -> None:
        t = TargetRef(url="https://x.example/arcgis/rest/services", kind=TargetKind.ARCGIS_ROOT)
        assert t.service_path is None
        assert t.layer_id is None

    def test_frozen(self) -> None:
        t = TargetRef(url="https://x", kind=TargetKind.WEB_PAGE)
        with pytest.raises(ValidationError):
            t.url = "https://y"

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TargetRef(url="https://x", kind=TargetKind.WEB_PAGE, bogus="x")  # type: ignore[call-arg]


class TestEvidence:
    def test_default_empty(self) -> None:
        e = Evidence()
        assert e.notes == []
        assert e.request is None

    def test_with_request_response(self) -> None:
        e = Evidence(
            request=HttpRequestSummary(method="GET", url="https://x"),
            response=HttpResponseSummary(status=200, headers={"content-type": "application/json"}),
            matched="anonymous-write-capable",
            notes=["enumerated 5 layers"],
        )
        assert e.response is not None
        assert e.response.status == 200


class TestFinding:
    def _build(self, **overrides: object) -> Finding:
        defaults: dict[str, object] = {
            "check_id": "ARC-002",
            "title": "Anonymous write capability",
            "severity": Severity.CRITICAL,
            "target": TargetRef(url="https://x.example/arcgis/rest", kind=TargetKind.ARCGIS_ROOT),
            "description": "FeatureServer accepts anonymous addFeatures.",
            "evidence": Evidence(notes=["capability=Create,Update,Delete"]),
            "remediation": "Restrict anonymous role.",
            "discovered_at": datetime(2026, 5, 3, tzinfo=UTC),
            "scan_id": "test-scan",
        }
        defaults.update(overrides)
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_construction(self) -> None:
        f = self._build(kvkk_articles=["m12"], gdpr_articles=["art32"], cwe="CWE-862")
        assert f.kvkk_articles == ["m12"]
        assert f.gdpr_articles == ["art32"]
        assert f.cwe == "CWE-862"

    def test_json_roundtrip_preserves_severity(self) -> None:
        f = self._build()
        payload = json.loads(f.model_dump_json())
        assert payload["severity"] == "critical"

    def test_json_roundtrip_preserves_compliance(self) -> None:
        f = self._build(kvkk_articles=["m12", "m9"], gdpr_articles=["art32"])
        round_tripped = Finding.model_validate_json(f.model_dump_json())
        assert round_tripped == f
