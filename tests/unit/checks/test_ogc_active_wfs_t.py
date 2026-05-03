"""Unit tests for OGC-005 active WFS-T (DescribeFeatureType + Insert/Delete)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import respx
import structlog
from httpx import Response

from gisweep.checks.ogc._helpers import CACHE_KEY
from gisweep.core.context import Context
from gisweep.core.finding import Finding, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check
from gisweep.discovery.ogc_enum import (
    OgcCapabilities,
    OgcLayerRef,
    OgcServerFingerprint,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass

WFS_ENDPOINT = "https://gs.example/geoserver/wfs"
TYPE_NAME = "ns1:demo"


def _wfs_cap_with_transaction() -> OgcCapabilities:
    return OgcCapabilities(
        service="WFS",
        version="2.0.0",
        endpoint_url=WFS_ENDPOINT,
        fingerprint=OgcServerFingerprint("geoserver", "2.24.1", "GeoServer 2.24.1"),
        layers=(OgcLayerRef(name=TYPE_NAME, title=None, queryable=True),),
        operations=frozenset({"GetCapabilities", "GetFeature", "Transaction"}),
    )


_DESCRIBE_FT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<xsd:schema targetNamespace="http://gisweep.example/demo"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:gml="http://www.opengis.net/gml/3.2">
  <xsd:complexType name="demoType">
    <xsd:complexContent>
      <xsd:extension base="gml:AbstractFeatureType">
        <xsd:sequence>
          <xsd:element name="geom" type="gml:PointPropertyType"/>
          <xsd:element name="title" type="xsd:string" minOccurs="0"/>
        </xsd:sequence>
      </xsd:extension>
    </xsd:complexContent>
  </xsd:complexType>
  <xsd:element name="demo" substitutionGroup="gml:_Feature" type="ns1:demoType"/>
</xsd:schema>
"""


_INSERT_OK_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wfs:TransactionResponse xmlns:wfs="http://www.opengis.net/wfs/2.0">
  <wfs:TransactionSummary>
    <wfs:totalInserted>1</wfs:totalInserted>
  </wfs:TransactionSummary>
  <wfs:InsertResults>
    <wfs:Feature>
      <fes:ResourceId xmlns:fes="http://www.opengis.net/fes/2.0" rid="demo.42"/>
    </wfs:Feature>
  </wfs:InsertResults>
</wfs:TransactionResponse>
"""

_DELETE_OK_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wfs:TransactionResponse xmlns:wfs="http://www.opengis.net/wfs/2.0">
  <wfs:TransactionSummary>
    <wfs:totalDeleted>1</wfs:totalDeleted>
  </wfs:TransactionSummary>
</wfs:TransactionResponse>
"""

_INSERT_ERROR_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ows:ExceptionReport xmlns:ows="http://www.opengis.net/ows/1.1">
  <ows:Exception>
    <ows:ExceptionText>Authentication required</ows:ExceptionText>
  </ows:Exception>
</ows:ExceptionReport>
"""


@pytest.fixture
async def ctx_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(active=True, i_own_this_target=True)
    http = HttpClient(options)
    yield Context(
        scan_id="scan-wfs-t",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


@pytest.fixture
async def ctx_passive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-wfs-t-passive",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


async def _collect(ctx: Context) -> list[Finding]:
    cls = get_check("OGC-005")
    assert cls is not None
    target = TargetRef(url=WFS_ENDPOINT, kind=TargetKind.OGC_SERVICE)
    return [f async for f in cls().run(target, ctx)]


@respx.mock
async def test_ogc005_active_records_add_and_delete_in_audit(
    ctx_active: Context, tmp_path: Path
) -> None:
    ctx_active.cache[CACHE_KEY] = [_wfs_cap_with_transaction()]
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*REQUEST=DescribeFeatureType.*").mock(
        return_value=Response(
            200, text=_DESCRIBE_FT_XML, headers={"Content-Type": "application/xml"}
        )
    )
    insert_route = respx.post(WFS_ENDPOINT).mock(
        side_effect=[
            Response(200, text=_INSERT_OK_RESPONSE, headers={"Content-Type": "application/xml"}),
            Response(200, text=_DELETE_OK_RESPONSE, headers={"Content-Type": "application/xml"}),
        ]
    )

    findings = await _collect(ctx_active)
    assert len(findings) == 1
    assert "verified" in findings[0].description.lower()
    assert insert_route.call_count == 2

    audit = [
        json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines() if line
    ]
    actions = [e["action"] for e in audit]
    assert actions == ["wfs-feature-add", "wfs-feature-delete"]
    assert audit[0]["details"]["feature_id"] == "demo.42"
    assert audit[1]["outcome"] == "success"


@respx.mock
async def test_ogc005_active_passes_through_when_insert_rejected(
    ctx_active: Context, tmp_path: Path
) -> None:
    ctx_active.cache[CACHE_KEY] = [_wfs_cap_with_transaction()]
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*REQUEST=DescribeFeatureType.*").mock(
        return_value=Response(
            200, text=_DESCRIBE_FT_XML, headers={"Content-Type": "application/xml"}
        )
    )
    respx.post(WFS_ENDPOINT).mock(
        return_value=Response(
            200, text=_INSERT_ERROR_RESPONSE, headers={"Content-Type": "application/xml"}
        )
    )

    findings = await _collect(ctx_active)
    assert len(findings) == 1
    assert "active probe failed" in findings[0].description.lower()

    audit = [
        json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines() if line
    ]
    assert len(audit) == 1
    assert audit[0]["action"] == "wfs-feature-add"
    assert audit[0]["outcome"] == "failure"


@respx.mock
async def test_ogc005_passive_unchanged(ctx_passive: Context) -> None:
    ctx_passive.cache[CACHE_KEY] = [_wfs_cap_with_transaction()]
    findings = await _collect(ctx_passive)
    assert len(findings) == 1
    # passive description includes the verification suggestion
    assert "re-run with ``--active" in findings[0].description.lower()
