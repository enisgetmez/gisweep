"""Unit tests for the ``scan`` auto-detect dispatcher."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import respx
from httpx import Response

from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.runtime.auto import TargetKindGuess, detect

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@pytest.fixture
async def http() -> AsyncIterator[HttpClient]:
    client = HttpClient(ScanOptions())
    yield client
    await client.aclose()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.example/arcgis/rest/services", TargetKindGuess.ARCGIS),
        ("https://x.example/server/rest/services/foo/MapServer", TargetKindGuess.ARCGIS),
        ("https://gs.example/geoserver/wms", TargetKindGuess.OGC),
        ("https://m.example/wfs", TargetKindGuess.OGC),
        ("https://m.example/cgi-bin/mapserv", TargetKindGuess.OGC),
    ],
)
async def test_detect_via_url_pattern(
    http: HttpClient, url: str, expected: TargetKindGuess
) -> None:
    assert await detect(url, http=http) is expected


@respx.mock
async def test_detect_via_arcgis_json_response(http: HttpClient) -> None:
    url = "https://opaque.example/services"
    respx.get(url).mock(
        return_value=Response(
            200,
            json={"currentVersion": 11.2, "services": []},
            headers={"Content-Type": "application/json"},
        )
    )
    assert await detect(url, http=http) is TargetKindGuess.ARCGIS


@respx.mock
async def test_detect_via_ogc_xml_response(http: HttpClient) -> None:
    url = "https://opaque.example/wms-like"
    respx.get(url).mock(
        return_value=Response(
            200,
            text='<?xml version="1.0"?><WMS_Capabilities version="1.3.0"></WMS_Capabilities>',
            headers={"Content-Type": "application/xml"},
        )
    )
    assert await detect(url, http=http) is TargetKindGuess.OGC


@respx.mock
async def test_detect_via_html_falls_back_to_web(http: HttpClient) -> None:
    url = "https://city.example/map"
    respx.get(url).mock(
        return_value=Response(
            200,
            text="<!doctype html><html><body><div id='map'></div></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
    )
    assert await detect(url, http=http) is TargetKindGuess.WEB


@respx.mock
async def test_detect_returns_unknown_on_error(http: HttpClient) -> None:
    url = "https://gone.example/whatever"
    respx.get(url).mock(side_effect=ConnectionError("dns fail"))
    assert await detect(url, http=http) is TargetKindGuess.UNKNOWN
