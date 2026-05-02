"""Unit tests for the ArcGIS discovery walker (respx-mocked HTTP)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
import respx
from httpx import Response

from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.discovery.arcgis_enum import ArcGISEnumerator, _parse_capabilities

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

ROOT = "https://x.example/arcgis/rest/services"


def _root_payload() -> dict[str, Any]:
    return {
        "currentVersion": 10.91,
        "folders": ["Public"],
        "services": [{"name": "Citizen", "type": "FeatureServer"}],
    }


def _public_folder_payload() -> dict[str, Any]:
    return {
        "currentVersion": 10.91,
        "folders": [],
        "services": [{"name": "Public/Streets", "type": "MapServer"}],
    }


def _feature_service_payload() -> dict[str, Any]:
    return {
        "capabilities": "Query,Create,Update,Delete",
        "layers": [{"id": 0, "name": "People"}],
        "tables": [{"id": 1, "name": "Audit"}],
    }


def _layer0_payload() -> dict[str, Any]:
    return {
        "id": 0,
        "name": "People",
        "geometryType": "esriGeometryPoint",
        "capabilities": "Query,Create,Update",
        "maxRecordCount": 2000,
        "hasAttachments": False,
        "fields": [
            {"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"},
            {"name": "TCKN", "alias": "TCKN", "type": "esriFieldTypeString", "length": 11},
            {"name": "Email", "alias": "E-Posta", "type": "esriFieldTypeString", "length": 80},
        ],
    }


def _table1_payload() -> dict[str, Any]:
    return {
        "id": 1,
        "name": "Audit",
        "capabilities": "Query",
        "fields": [{"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"}],
    }


@pytest.fixture
async def http() -> AsyncIterator[HttpClient]:
    client = HttpClient(ScanOptions())
    yield client
    await client.aclose()


@respx.mock
async def test_root_info_parses_payload(http: HttpClient) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload()))
    enumerator = ArcGISEnumerator(http, ROOT)
    info = await enumerator.root_info()
    assert info["currentVersion"] == 10.91
    assert info["folders"] == ["Public"]


@respx.mock
async def test_walk_recurses_into_folders(http: HttpClient) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload()))
    respx.get(f"{ROOT}/Public?f=json").mock(
        return_value=Response(200, json=_public_folder_payload())
    )
    enumerator = ArcGISEnumerator(http, ROOT)
    services = [svc async for svc in enumerator.walk()]
    names = {(svc.folder, svc.name, svc.type) for svc in services}
    assert (None, "Citizen", "FeatureServer") in names
    assert ("Public", "Streets", "MapServer") in names


@respx.mock
async def test_layers_yields_layers_and_tables(http: HttpClient) -> None:
    respx.get(f"{ROOT}?f=json").mock(return_value=Response(200, json=_root_payload()))
    respx.get(f"{ROOT}/Citizen/FeatureServer?f=json").mock(
        return_value=Response(200, json=_feature_service_payload())
    )
    respx.get(f"{ROOT}/Citizen/FeatureServer/0?f=json").mock(
        return_value=Response(200, json=_layer0_payload())
    )
    respx.get(f"{ROOT}/Citizen/FeatureServer/1?f=json").mock(
        return_value=Response(200, json=_table1_payload())
    )
    enumerator = ArcGISEnumerator(http, ROOT)
    services = [svc async for svc in enumerator.walk(max_depth=0)]
    citizen = next(svc for svc in services if svc.name == "Citizen")
    layers = [layer async for layer in enumerator.layers(citizen)]
    assert {layer.layer_id for layer in layers} == {0, 1}
    people = next(layer for layer in layers if layer.layer_id == 0)
    assert {field_.name for field_ in people.fields} == {"OBJECTID", "TCKN", "Email"}
    assert "Create" in people.capabilities


@respx.mock
async def test_token_appended_to_query(http: HttpClient) -> None:
    route = respx.get(url__regex=rf"{ROOT}\?.*token=secret-tok").mock(
        return_value=Response(200, json=_root_payload())
    )
    enumerator = ArcGISEnumerator(http, ROOT, token="secret-tok")
    await enumerator.root_info()
    assert route.called


def test_parse_capabilities_handles_string_and_list() -> None:
    assert _parse_capabilities({"capabilities": "Create,Update,Delete"}) == frozenset(
        {"Create", "Update", "Delete"}
    )
    assert _parse_capabilities({"capabilities": ["Query", "Editing"]}) == frozenset(
        {"Query", "Editing"}
    )
    assert _parse_capabilities({}) == frozenset()
