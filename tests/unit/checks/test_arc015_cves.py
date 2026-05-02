"""Unit tests for ARC-015 (outdated ArcGIS Server with known CVE)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import respx
import structlog
from httpx import Response

from gisweep.checks.arcgis.cves import normalize_arcgis_server_version
from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check
from gisweep.cve.db import (
    CveDatabase,
    CveRecord,
    CveSeverity,
    VersionRange,
    get_cve_database,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path
    pass

ROOT = "https://x.example/arcgis/rest/services"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-arc015",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


def _root_payload(version: str) -> dict[str, object]:
    return {
        "currentVersion": version,
        "folders": [],
        "services": [],
    }


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("10.91", "10.9.1"),
        ("10.31", "10.3.1"),
        ("10.81", "10.8.1"),
        ("10.7.1", "10.7.1"),
        ("10.5", "10.5"),
        ("11.2", "11.2"),
        ("11.3.1", "11.3.1"),
        ("  10.91  ", "10.9.1"),
    ],
)
def test_normalize_arcgis_server_version(raw: str, normalized: str) -> None:
    assert normalize_arcgis_server_version(raw) == normalized


def _seeded_database(version_to_match: str) -> CveDatabase:
    return CveDatabase(
        schema_version=1,
        generated_at=None,
        source=None,
        products={
            "esri:arcgis_server": (
                CveRecord(
                    cve_id="CVE-2020-35712",
                    summary="SSRF in ArcGIS Server before 10.8.",
                    severity=CveSeverity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    published=None,
                    references=("https://nvd.nist.gov/vuln/detail/CVE-2020-35712",),
                    ranges=(VersionRange(introduced=None, fixed="10.8"),),
                ),
                CveRecord(
                    cve_id="CVE-9999-0001",
                    summary="Test entry that matches an exact version.",
                    severity=CveSeverity.HIGH,
                    cvss_score=7.5,
                    cvss_vector=None,
                    published=None,
                    references=(),
                    ranges=(VersionRange(introduced=None, fixed=None, exact=version_to_match),),
                ),
            )
        },
    )


async def _collect(target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check("ARC-015")
    assert cls is not None
    instance = cls()
    return [f async for f in instance.run(target, ctx)]


@respx.mock
async def test_arc015_emits_findings_for_affected_version(ctx: Context) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload("10.31")))
    db = _seeded_database("10.3.1")
    get_cve_database.cache_clear()
    with patch("gisweep.checks.arcgis.cves.get_cve_database", return_value=db):
        findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    cve_ids = {f.tags[-1] for f in findings}
    assert "CVE-2020-35712" in cve_ids  # 10.3.1 < 10.8
    assert "CVE-9999-0001" in cve_ids  # exact match on the normalized form
    by_id = {f.tags[-1]: f for f in findings}
    assert by_id["CVE-2020-35712"].severity is Severity.CRITICAL
    assert by_id["CVE-9999-0001"].severity is Severity.HIGH


@respx.mock
async def test_arc015_silent_when_version_is_patched(ctx: Context) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload("11.2")))
    db = _seeded_database("10.3.1")
    get_cve_database.cache_clear()
    with patch("gisweep.checks.arcgis.cves.get_cve_database", return_value=db):
        findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert findings == []


@respx.mock
async def test_arc015_silent_when_database_empty(ctx: Context) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload("10.31")))
    db = CveDatabase(
        schema_version=1,
        generated_at=None,
        source=None,
        products={"esri:arcgis_server": ()},
    )
    get_cve_database.cache_clear()
    with patch("gisweep.checks.arcgis.cves.get_cve_database", return_value=db):
        findings = await _collect(TargetRef(url=ROOT, kind=TargetKind.ARCGIS_ROOT), ctx)
    assert findings == []
