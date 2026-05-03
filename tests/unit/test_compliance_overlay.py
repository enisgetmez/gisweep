"""Unit tests for the compliance overlay (COMP-001, COMP-003)."""

from __future__ import annotations

from datetime import UTC, datetime

from gisweep.compliance import apply_overlay
from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef


def _f(
    check_id: str, severity: Severity = Severity.HIGH, url: str = "https://x.example"
) -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        severity=severity,
        target=TargetRef(url=url, kind=TargetKind.ARCGIS_LAYER),
        description="x",
        evidence=Evidence(),
        remediation="x",
        kvkk_articles=["m12"],
        gdpr_articles=["art32"],
        discovered_at=datetime.now(tz=UTC),
        scan_id="scan-test",
    )


def test_overlay_returns_originals_unchanged() -> None:
    findings = [_f("ARC-001"), _f("ARC-002")]
    out = apply_overlay(findings, scan_id="scan-test")
    assert out[: len(findings)] == findings


def test_comp001_fires_when_five_pii_findings_present() -> None:
    findings = [_f("ARC-014", url=f"https://x.example/layer/{i}") for i in range(5)]
    out = apply_overlay(findings, scan_id="scan-test")
    comp = [f for f in out if f.check_id == "COMP-001"]
    assert len(comp) == 1
    assert comp[0].severity is Severity.CRITICAL
    assert "m12" in comp[0].kvkk_articles


def test_comp001_silent_with_four_pii_findings() -> None:
    findings = [_f("ARC-014", url=f"https://x.example/layer/{i}") for i in range(4)]
    out = apply_overlay(findings, scan_id="scan-test")
    assert all(f.check_id != "COMP-001" for f in out)


def test_comp003_fires_when_admin_plus_data() -> None:
    findings = [
        _f("ARC-003", severity=Severity.CRITICAL),
        _f("ARC-001", severity=Severity.INFO),
    ]
    out = apply_overlay(findings, scan_id="scan-test")
    comp = [f for f in out if f.check_id == "COMP-003"]
    assert len(comp) == 1
    assert comp[0].severity is Severity.CRITICAL


def test_comp003_silent_when_only_admin() -> None:
    findings = [_f("ARC-003", severity=Severity.CRITICAL)]
    out = apply_overlay(findings, scan_id="scan-test")
    assert all(f.check_id != "COMP-003" for f in out)


def test_comp003_silent_when_only_data_findings() -> None:
    findings = [_f("ARC-001", severity=Severity.INFO), _f("ARC-014")]
    out = apply_overlay(findings, scan_id="scan-test")
    assert all(f.check_id != "COMP-003" for f in out)


def test_comp003_triggers_on_ogc005_too() -> None:
    findings = [_f("ARC-003", severity=Severity.CRITICAL), _f("OGC-005")]
    out = apply_overlay(findings, scan_id="scan-test")
    assert any(f.check_id == "COMP-003" for f in out)
