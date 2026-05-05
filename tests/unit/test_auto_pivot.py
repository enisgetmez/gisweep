"""Tests for the ``scan`` web → arcgis/ogc pivot orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef
from gisweep.core.runner import ScanMeta
from gisweep.discovery.browser import CapturedRequest, WebDiscoveryResult
from gisweep.runtime import arcgis as arcgis_runtime
from gisweep.runtime import auto
from gisweep.runtime import ogc as ogc_runtime
from gisweep.runtime import web as web_runtime

if TYPE_CHECKING:
    from pathlib import Path

    from rich.console import Console


def _meta(scan_id: str, exit_code: int = 0) -> ScanMeta:
    return ScanMeta(
        scan_id=scan_id,
        started_at=datetime(2026, 5, 5, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 5, 12, 0, 1, tzinfo=UTC),
        targets=("https://x.gov",),
        gisweep_version="0.1.0",
        exit_code=exit_code,
        counts_by_severity=dict.fromkeys(Severity, 0),
    )


def _finding(check_id: str, url: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"{check_id} title",
        severity=severity,
        target=TargetRef(url=url, kind=TargetKind.ARCGIS_LAYER),
        description="x",
        evidence=Evidence(matched="x"),
        remediation="x",
        kvkk_articles=["m12"],
        gdpr_articles=["art32"],
        discovered_at=datetime.now(tz=UTC),
        scan_id="test",
    )


def _captured(url: str) -> CapturedRequest:
    return CapturedRequest(
        url=url,
        method="GET",
        resource_type="xhr",
        response_status=200,
        response_headers=(),
    )


def _discovery(*urls: str) -> WebDiscoveryResult:
    return WebDiscoveryResult(
        page_url="https://portal.example.bel.tr/Harita",
        final_url="https://portal.example.bel.tr/Harita",
        requests=[_captured(u) for u in urls],
        libraries=[],
        bodies=[],
        page_html="<html></html>",
    )


async def _stub_crawl_and_check(
    request: web_runtime.ScanRequest,
    *,
    console: Console | None = None,
) -> tuple[list[Finding], ScanMeta, WebDiscoveryResult]:
    discovery = _discovery(
        # Same-domain GeoServer, multiple URL variants — should collapse to one pivot.
        "https://geoserver.example.bel.tr/geoserver/foo/wms?service=WMS&request=GetMap",
        "https://geoserver.example.bel.tr/geoserver/foo/wms?service=WMS&request=GetMap&layers=other",
        # Same-domain ArcGIS endpoint — second pivot.
        "https://gis.example.bel.tr/arcgis/rest/services/Foo/MapServer/0/query",
        # Third-party tile/API — must be filtered out.
        "https://api.mapbox.com/styles/v1/foo",
        "https://maps.googleapis.com/maps/api/js?key=AIzaSyDFAKE",
    )
    return (
        [_finding("WEB-001", "https://portal.example.bel.tr/Harita")],
        _meta("scan-web", exit_code=0),
        discovery,
    )


async def _stub_arcgis_scan_only(
    request: arcgis_runtime.ScanRequest,
    *,
    console: Console | None = None,
) -> tuple[list[Finding], ScanMeta]:
    return (
        [_finding("ARC-002", request.url, severity=Severity.CRITICAL)],
        _meta(request.scan_id, exit_code=1),
    )


async def _stub_ogc_scan_only(
    request: ogc_runtime.ScanRequest,
    *,
    console: Console | None = None,
) -> tuple[list[Finding], ScanMeta]:
    return (
        [_finding("OGC-001", request.url)],
        _meta(request.scan_id, exit_code=1),
    )


@pytest.fixture
def stub_runtimes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_runtime, "crawl_and_check", _stub_crawl_and_check)
    monkeypatch.setattr(arcgis_runtime, "scan_only", _stub_arcgis_scan_only)
    monkeypatch.setattr(ogc_runtime, "scan_only", _stub_ogc_scan_only)


async def test_pivot_runs_arcgis_and_ogc_and_aggregates(
    stub_runtimes: None, tmp_path: Path
) -> None:
    request = auto.DispatchRequest(
        url="https://portal.example.bel.tr/Harita",
        scan_id="scan-001",
        output_dir=tmp_path,
        outputs=(),
        timeout=30.0,
        verify_tls=True,
    )
    exit_code = await auto._run_web_with_pivot(request, console=None)
    # Web run + arcgis pivot returned exit_code=1 → combined keeps the highest.
    assert exit_code == 1


async def test_pivot_collapses_duplicate_urls_to_one_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arcgis_calls: list[str] = []
    ogc_calls: list[str] = []

    async def record_arcgis(
        req: arcgis_runtime.ScanRequest, *, console: Console | None = None
    ) -> tuple[list[Finding], ScanMeta]:
        arcgis_calls.append(req.url)
        return [], _meta(req.scan_id)

    async def record_ogc(
        req: ogc_runtime.ScanRequest, *, console: Console | None = None
    ) -> tuple[list[Finding], ScanMeta]:
        ogc_calls.append(req.url)
        return [], _meta(req.scan_id)

    monkeypatch.setattr(web_runtime, "crawl_and_check", _stub_crawl_and_check)
    monkeypatch.setattr(arcgis_runtime, "scan_only", record_arcgis)
    monkeypatch.setattr(ogc_runtime, "scan_only", record_ogc)

    request = auto.DispatchRequest(
        url="https://portal.example.bel.tr/Harita",
        scan_id="scan-002",
        output_dir=tmp_path,
        outputs=(),
        timeout=30.0,
        verify_tls=True,
    )
    await auto._run_web_with_pivot(request, console=None)

    # Two GeoServer URL variants → one pivot. One ArcGIS URL → one pivot.
    # Mapbox + Google Maps URLs are third-party → zero pivots.
    assert ogc_calls == ["https://geoserver.example.bel.tr/geoserver"]
    assert arcgis_calls == ["https://gis.example.bel.tr/arcgis/rest/services"]


async def test_pivot_skips_when_no_same_domain_endpoints(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arcgis_called = False
    ogc_called = False

    async def empty_crawl(
        request: web_runtime.ScanRequest,
        *,
        console: Console | None = None,
    ) -> tuple[list[Finding], ScanMeta, WebDiscoveryResult]:
        return (
            [],
            _meta("scan-web"),
            _discovery("https://api.mapbox.com/styles/v1/foo"),
        )

    async def fail_arcgis(
        req: arcgis_runtime.ScanRequest, *, console: Console | None = None
    ) -> tuple[list[Finding], ScanMeta]:
        nonlocal arcgis_called
        arcgis_called = True
        return [], _meta(req.scan_id)

    async def fail_ogc(
        req: ogc_runtime.ScanRequest, *, console: Console | None = None
    ) -> tuple[list[Finding], ScanMeta]:
        nonlocal ogc_called
        ogc_called = True
        return [], _meta(req.scan_id)

    monkeypatch.setattr(web_runtime, "crawl_and_check", empty_crawl)
    monkeypatch.setattr(arcgis_runtime, "scan_only", fail_arcgis)
    monkeypatch.setattr(ogc_runtime, "scan_only", fail_ogc)

    request = auto.DispatchRequest(
        url="https://www.x.gov/portal",
        scan_id="scan-003",
        output_dir=tmp_path,
        outputs=(),
        timeout=30.0,
        verify_tls=True,
    )
    await auto._run_web_with_pivot(request, console=None)
    assert arcgis_called is False
    assert ogc_called is False
