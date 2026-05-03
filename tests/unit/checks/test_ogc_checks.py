"""Unit tests for OGC-001/OGC-002/OGC-005."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import structlog

from gisweep.checks.ogc._helpers import CACHE_KEY
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
from gisweep.discovery.ogc_enum import (
    OgcCapabilities,
    OgcLayerRef,
    OgcServerFingerprint,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass

ENDPOINT = "https://gs.example/geoserver/wms"
WFS_ENDPOINT = "https://gs.example/geoserver/wfs"


@pytest.fixture
async def ctx(tmp_path: Path) -> AsyncIterator[Context]:
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-ogc",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


def _wms_cap(software: str = "geoserver", version: str | None = "2.24.1") -> OgcCapabilities:
    return OgcCapabilities(
        service="WMS",
        version="1.3.0",
        endpoint_url=ENDPOINT,
        fingerprint=OgcServerFingerprint(
            software=software, version=version, raw_signature=f"{software} {version}"
        ),
        layers=(OgcLayerRef(name="citizen:addresses", title="Addresses", queryable=True),),
        operations=frozenset({"GetCapabilities", "GetMap", "GetFeatureInfo"}),
    )


def _wfs_cap(operations: frozenset[str]) -> OgcCapabilities:
    return OgcCapabilities(
        service="WFS",
        version="2.0.0",
        endpoint_url=WFS_ENDPOINT,
        fingerprint=OgcServerFingerprint("geoserver", "2.20.4", "GeoServer 2.20.4"),
        layers=(OgcLayerRef(name="citizen:people", title=None, queryable=True),),
        operations=operations,
    )


async def _collect(check_id: str, target: TargetRef, ctx: Context) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    instance = cls()
    return [f async for f in instance.run(target, ctx)]


async def test_ogc001_emits_info_finding(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_wms_cap()]
    findings = await _collect("OGC-001", TargetRef(url=ENDPOINT, kind=TargetKind.OGC_SERVICE), ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "WMS 1.3.0" in findings[0].title


async def test_ogc002_matches_geoserver_cve(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_wms_cap(software="geoserver", version="2.20.0")]
    db = CveDatabase(
        schema_version=1,
        generated_at=None,
        source=None,
        products={
            "osgeo:geoserver": (
                CveRecord(
                    cve_id="CVE-2024-36401",
                    summary="GeoServer RCE in eval evaluation.",
                    severity=CveSeverity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    published=None,
                    references=("https://nvd.nist.gov/vuln/detail/CVE-2024-36401",),
                    ranges=(VersionRange(introduced=None, fixed="2.21.4"),),
                ),
            )
        },
    )
    get_cve_database.cache_clear()
    with patch("gisweep.checks.ogc.cves.get_cve_database", return_value=db):
        findings = await _collect(
            "OGC-002", TargetRef(url=ENDPOINT, kind=TargetKind.OGC_SERVICE), ctx
        )
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "CVE-2024-36401" in findings[0].tags


async def test_ogc002_silent_when_software_unknown(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_wms_cap(software="unknown", version=None)]
    findings = await _collect("OGC-002", TargetRef(url=ENDPOINT, kind=TargetKind.OGC_SERVICE), ctx)
    assert findings == []


async def test_ogc005_flags_wfs_t_when_anonymous(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [
        _wfs_cap(operations=frozenset({"GetCapabilities", "GetFeature", "Transaction"}))
    ]
    findings = await _collect(
        "OGC-005", TargetRef(url=WFS_ENDPOINT, kind=TargetKind.OGC_SERVICE), ctx
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert "Transaction" in (findings[0].evidence.matched or "")


async def test_ogc005_silent_when_no_transactional_op(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_wfs_cap(operations=frozenset({"GetCapabilities", "GetFeature"}))]
    findings = await _collect(
        "OGC-005", TargetRef(url=WFS_ENDPOINT, kind=TargetKind.OGC_SERVICE), ctx
    )
    assert findings == []
