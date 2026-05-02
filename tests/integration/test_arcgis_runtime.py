"""End-to-end integration test for the arcgis subcommand."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest  # noqa: F401  -- needed for fixture decorators referenced indirectly
import respx
from httpx import Response
from typer.testing import CliRunner

import gisweep.checks  # noqa: F401  -- side-effect: register built-in checks
from gisweep.cli import app

if TYPE_CHECKING:
    from pathlib import Path

ROOT = "https://x.example/arcgis/rest/services"


@respx.mock
def test_arcgis_subcommand_writes_json_and_exits_one(tmp_path: Path) -> None:
    respx.get(f"{ROOT}?f=json").mock(
        return_value=Response(
            200,
            json={
                "currentVersion": 10.91,
                "folders": [],
                "services": [{"name": "Citizen", "type": "FeatureServer"}],
            },
        )
    )
    respx.get(f"{ROOT}/Citizen/FeatureServer?f=json").mock(
        return_value=Response(
            200,
            json={
                "capabilities": "Query,Create,Update,Delete",
                "layers": [{"id": 0, "name": "People"}],
                "tables": [],
            },
        )
    )
    respx.get(f"{ROOT}/Citizen/FeatureServer/0?f=json").mock(
        return_value=Response(
            200,
            json={
                "id": 0,
                "name": "People",
                "geometryType": "esriGeometryPoint",
                "capabilities": "Query,Create,Update,Delete",
                "maxRecordCount": 100000,
                "fields": [
                    {"name": "OBJECTID", "alias": "OBJECTID", "type": "esriFieldTypeOID"},
                    {"name": "TCKN", "alias": "TCKN", "type": "esriFieldTypeString"},
                ],
            },
        )
    )
    respx.get(url__regex=r"https://x\.example/arcgis/(admin|portaladmin)/?").mock(
        return_value=Response(404)
    )

    out_json = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        ["arcgis", ROOT, "-o", str(out_json), "--severity-threshold", "info"],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.stdout
    payload = json.loads(out_json.read_text())
    ids = {f["check_id"] for f in payload["findings"]}
    assert "ARC-001" in ids
    assert "ARC-002" in ids
    assert "ARC-013" in ids
    assert "ARC-014" in ids


def test_arcgis_active_without_ownership_flag_aborts() -> None:
    result = CliRunner().invoke(
        app, ["arcgis", "https://x.example/arcgis/rest/services", "--active"]
    )
    assert result.exit_code == 2
    assert "i-own-this-target" in result.stdout
