"""Unit tests for the OGC data-exposure checks (OGC-006 / OGC-007 / OGC-008)
and the GeoServer CVE-2024-36401 active probe (GEO-001)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx as _httpx
import pytest
import respx
import structlog
from httpx import Response

from gisweep.checks.ogc._helpers import CACHE_KEY
from gisweep.core.context import Context
from gisweep.core.finding import Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import get_check
from gisweep.discovery.ogc_enum import (
    OgcCapabilities,
    OgcLayerRef,
    OgcServerFingerprint,
)
from gisweep.discovery.wfs_schema import describe_feature_type

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


WFS_ENDPOINT = "https://gs.example/geoserver/wfs"
PII_TYPE_NAME = "city:adresler"
SAFE_TYPE_NAME = "city:durak"


def _cap(layer_names: tuple[str, ...]) -> OgcCapabilities:
    return OgcCapabilities(
        service="WFS",
        version="2.0.0",
        endpoint_url=WFS_ENDPOINT,
        fingerprint=OgcServerFingerprint("geoserver", "2.24.1", "GeoServer 2.24.1"),
        layers=tuple(OgcLayerRef(name=n, title=None, queryable=True) for n in layer_names),
        operations=frozenset({"GetCapabilities", "GetFeature", "DescribeFeatureType"}),
    )


_PII_SCHEMA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<xsd:schema targetNamespace="http://gisweep.example/city"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:gml="http://www.opengis.net/gml/3.2">
  <xsd:complexType name="adreslerType">
    <xsd:sequence>
      <xsd:element name="geom" type="gml:PointPropertyType"/>
      <xsd:element name="tckn" type="xsd:string"/>
      <xsd:element name="email" type="xsd:string"/>
      <xsd:element name="adres" type="xsd:string"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:element name="adresler" type="city:adreslerType"/>
</xsd:schema>
"""

_SAFE_SCHEMA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<xsd:schema targetNamespace="http://gisweep.example/city"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:gml="http://www.opengis.net/gml/3.2">
  <xsd:complexType name="durakType">
    <xsd:sequence>
      <xsd:element name="geom" type="gml:PointPropertyType"/>
      <xsd:element name="durak_adi" type="xsd:string"/>
    </xsd:sequence>
  </xsd:complexType>
  <xsd:element name="durak" type="city:durakType"/>
</xsd:schema>
"""

_GETFEATURE_HUGE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wfs:FeatureCollection xmlns:wfs="http://www.opengis.net/wfs/2.0"
  xmlns:city="http://gisweep.example/city"
  numberMatched="42117" numberReturned="1">
  <wfs:member><city:adresler/></wfs:member>
</wfs:FeatureCollection>
"""

_GETFEATURE_SMALL_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wfs:FeatureCollection xmlns:wfs="http://www.opengis.net/wfs/2.0"
  xmlns:city="http://gisweep.example/city"
  numberMatched="12" numberReturned="1">
  <wfs:member><city:durak/></wfs:member>
</wfs:FeatureCollection>
"""

_GETFEATURE_REQUIRES_AUTH = """<ows:ExceptionReport xmlns:ows="http://www.opengis.net/ows/1.1">
  <ows:Exception><ows:ExceptionText>Authentication required</ows:ExceptionText></ows:Exception>
</ows:ExceptionReport>"""


@pytest.fixture
async def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions()
    http = HttpClient(options)
    yield Context(
        scan_id="scan-ogc-data",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


@pytest.fixture
async def ctx_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Context]:
    monkeypatch.setenv("GISWEEP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    options = ScanOptions(active=True, i_own_this_target=True)
    http = HttpClient(options)
    yield Context(
        scan_id="scan-ogc-active",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    await http.aclose()


def _layer_target(type_name: str) -> TargetRef:
    return TargetRef(url=WFS_ENDPOINT, kind=TargetKind.OGC_LAYER, service_path=type_name)


def _service_target() -> TargetRef:
    return TargetRef(url=WFS_ENDPOINT, kind=TargetKind.OGC_SERVICE)


async def _collect(check_id: str, ctx: Context, target: TargetRef) -> list[Finding]:
    cls = get_check(check_id)
    assert cls is not None
    return [f async for f in cls().run(target, ctx)]


def _mock_describe(type_name: str, body: str) -> None:
    encoded = type_name.replace(":", "%3A")
    pattern = rf"{WFS_ENDPOINT}\?.*REQUEST=DescribeFeatureType.*TYPENAMES={encoded}.*"
    respx.get(url__regex=pattern).mock(
        return_value=Response(200, text=body, headers={"Content-Type": "application/xml"})
    )


def _mock_getfeature(type_name: str, body: str, status: int = 200) -> None:
    encoded = type_name.replace(":", "%3A")
    pattern = rf"{WFS_ENDPOINT}\?.*REQUEST=GetFeature.*TYPENAMES={encoded}.*"
    respx.get(url__regex=pattern).mock(
        return_value=Response(status, text=body, headers={"Content-Type": "application/xml"})
    )


# ----------------------------------------------------------------------------
# OGC-006 PII fields
# ----------------------------------------------------------------------------


@respx.mock
async def test_ogc006_fires_critical_when_pii_field_anonymously_readable(
    ctx: Context,
) -> None:
    ctx.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    _mock_describe(PII_TYPE_NAME, _PII_SCHEMA_XML)
    _mock_getfeature(PII_TYPE_NAME, _GETFEATURE_HUGE_RESPONSE)
    findings = await _collect("OGC-006", ctx, _layer_target(PII_TYPE_NAME))
    assert len(findings) == 1
    assert findings[0].severity in {Severity.HIGH, Severity.CRITICAL}
    matched = findings[0].evidence.matched
    assert matched is not None
    assert "tckn" in matched.lower()


@respx.mock
async def test_ogc006_demoted_when_anonymous_read_blocked(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    _mock_describe(PII_TYPE_NAME, _PII_SCHEMA_XML)
    _mock_getfeature(PII_TYPE_NAME, _GETFEATURE_REQUIRES_AUTH, status=401)
    findings = await _collect("OGC-006", ctx, _layer_target(PII_TYPE_NAME))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


@respx.mock
async def test_ogc006_silent_when_no_pii_match(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((SAFE_TYPE_NAME,))]
    _mock_describe(SAFE_TYPE_NAME, _SAFE_SCHEMA_XML)
    _mock_getfeature(SAFE_TYPE_NAME, _GETFEATURE_SMALL_RESPONSE)
    findings = await _collect("OGC-006", ctx, _layer_target(SAFE_TYPE_NAME))
    assert findings == []


# ----------------------------------------------------------------------------
# OGC-007 unbounded GetFeature
# ----------------------------------------------------------------------------


@respx.mock
async def test_ogc007_fires_on_high_cardinality_anonymous_read(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    _mock_describe(PII_TYPE_NAME, _PII_SCHEMA_XML)
    _mock_getfeature(PII_TYPE_NAME, _GETFEATURE_HUGE_RESPONSE)
    findings = await _collect("OGC-007", ctx, _layer_target(PII_TYPE_NAME))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    matched = findings[0].evidence.matched
    assert matched is not None
    assert "42117" in matched


@respx.mock
async def test_ogc007_silent_for_small_layers(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((SAFE_TYPE_NAME,))]
    _mock_describe(SAFE_TYPE_NAME, _SAFE_SCHEMA_XML)
    _mock_getfeature(SAFE_TYPE_NAME, _GETFEATURE_SMALL_RESPONSE)
    findings = await _collect("OGC-007", ctx, _layer_target(SAFE_TYPE_NAME))
    assert findings == []


# ----------------------------------------------------------------------------
# OGC-008 anonymous read confirmation
# ----------------------------------------------------------------------------


@respx.mock
async def test_ogc008_fires_when_member_returned(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((SAFE_TYPE_NAME,))]
    _mock_describe(SAFE_TYPE_NAME, _SAFE_SCHEMA_XML)
    _mock_getfeature(SAFE_TYPE_NAME, _GETFEATURE_SMALL_RESPONSE)
    findings = await _collect("OGC-008", ctx, _layer_target(SAFE_TYPE_NAME))
    assert len(findings) == 1
    matched = findings[0].evidence.matched
    assert matched is not None
    assert "durak_adi" in matched


@respx.mock
async def test_ogc008_silent_when_auth_required(ctx: Context) -> None:
    ctx.cache[CACHE_KEY] = [_cap((SAFE_TYPE_NAME,))]
    _mock_describe(SAFE_TYPE_NAME, _SAFE_SCHEMA_XML)
    _mock_getfeature(SAFE_TYPE_NAME, _GETFEATURE_REQUIRES_AUTH, status=401)
    findings = await _collect("OGC-008", ctx, _layer_target(SAFE_TYPE_NAME))
    assert findings == []


# ----------------------------------------------------------------------------
# GEO-001 CVE-2024-36401 active probe
# ----------------------------------------------------------------------------


_VULN_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<wfs:ValueCollection xmlns:wfs="http://www.opengis.net/wfs/2.0">
  <wfs:member>java.lang.Runtime</wfs:member>
</wfs:ValueCollection>"""

_PATCHED_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<ows:ExceptionReport xmlns:ows="http://www.opengis.net/ows/1.1">
  <ows:Exception exceptionCode="InvalidParameterValue">
    <ows:ExceptionText>valueReference: invalid property name</ows:ExceptionText>
  </ows:Exception>
</ows:ExceptionReport>"""


@respx.mock
async def test_geo001_fires_when_runtime_marker_returned(
    ctx_active: Context, tmp_path: Path
) -> None:
    ctx_active.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*REQUEST=GetPropertyValue.*").mock(
        return_value=Response(200, text=_VULN_RESPONSE)
    )

    findings = await _collect("GEO-001", ctx_active, _service_target())
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    matched = findings[0].evidence.matched
    assert matched is not None
    assert "java.lang.Runtime" in matched

    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert any(json.loads(line)["outcome"] == "success" for line in audit_lines if line)


@respx.mock
async def test_geo001_silent_on_patched_server(ctx_active: Context, tmp_path: Path) -> None:
    ctx_active.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*REQUEST=GetPropertyValue.*").mock(
        return_value=Response(400, text=_PATCHED_RESPONSE)
    )

    findings = await _collect("GEO-001", ctx_active, _service_target())
    assert findings == []
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert any(json.loads(line)["outcome"] == "skipped" for line in audit_lines if line)


@respx.mock
async def test_geo001_silent_without_active_opt_in(ctx: Context) -> None:
    """Without --active --i-own-this-target the probe never fires, even
    against a server that would return the vulnerable marker."""
    ctx.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    route = respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*").mock(
        return_value=Response(200, text=_VULN_RESPONSE)
    )
    findings = await _collect("GEO-001", ctx, _service_target())
    assert findings == []
    assert route.call_count == 0


@respx.mock
async def test_geo001_records_failure_on_network_error(ctx_active: Context, tmp_path: Path) -> None:
    """A connection error during the probe must still leave an audit trail
    so the operator knows the probe was attempted but didn't conclude."""
    ctx_active.cache[CACHE_KEY] = [_cap((PII_TYPE_NAME,))]
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*").mock(side_effect=_httpx.ConnectError("boom"))
    findings = await _collect("GEO-001", ctx_active, _service_target())
    assert findings == []
    audit_lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert any(json.loads(line)["outcome"] == "failure" for line in audit_lines if line)


@respx.mock
async def test_describe_feature_type_returns_none_on_bad_xml(ctx: Context) -> None:
    """The schema helper must swallow parser errors rather than blow up the
    check pipeline."""
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*").mock(
        return_value=Response(
            200, text="<not><well/></formed", headers={"Content-Type": "application/xml"}
        )
    )
    schema = await describe_feature_type(ctx, WFS_ENDPOINT, PII_TYPE_NAME)
    assert schema is None


@respx.mock
async def test_describe_feature_type_returns_none_on_http_error(ctx: Context) -> None:
    respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*").mock(side_effect=_httpx.ConnectError("boom"))
    schema = await describe_feature_type(ctx, WFS_ENDPOINT, PII_TYPE_NAME)
    assert schema is None


@respx.mock
async def test_geo001_silent_for_non_geoserver_fingerprint(ctx_active: Context) -> None:
    """MapServer / QGIS are not affected by CVE-2024-36401; we must not probe
    them with the GeoServer-specific payload."""
    cap = OgcCapabilities(
        service="WFS",
        version="2.0.0",
        endpoint_url=WFS_ENDPOINT,
        fingerprint=OgcServerFingerprint("mapserver", "8.0.1", "MapServer 8.0.1"),
        layers=(OgcLayerRef(name=PII_TYPE_NAME, title=None, queryable=True),),
        operations=frozenset({"GetCapabilities"}),
    )
    ctx_active.cache[CACHE_KEY] = [cap]
    route = respx.get(url__regex=rf"{WFS_ENDPOINT}\?.*").mock(
        return_value=Response(200, text=_VULN_RESPONSE)
    )
    findings = await _collect("GEO-001", ctx_active, _service_target())
    assert findings == []
    assert route.call_count == 0
