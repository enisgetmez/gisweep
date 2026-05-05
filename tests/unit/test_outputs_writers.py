"""Unit tests for the file-emitting output writers (JSON, SARIF, Markdown, HTML)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef
from gisweep.core.runner import ScanMeta
from gisweep.outputs.html import HtmlWriter
from gisweep.outputs.json_writer import SCHEMA_VERSION, JsonWriter
from gisweep.outputs.markdown import MarkdownWriter
from gisweep.outputs.registry import build_writer, parse_output_arg
from gisweep.outputs.sarif import SARIF_VERSION, SarifWriter

if TYPE_CHECKING:
    from pathlib import Path


def _meta() -> ScanMeta:
    return ScanMeta(
        scan_id="0123456789abcdef",
        started_at=datetime(2026, 5, 3, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 3, 12, 0, 1, 250000, tzinfo=UTC),
        targets=("https://x.example/arcgis/rest/services",),
        gisweep_version="0.2.0",
        exit_code=1,
        counts_by_severity={**dict.fromkeys(Severity, 0), Severity.CRITICAL: 1},
    )


def _finding(check_id: str = "ARC-002") -> Finding:
    return Finding(
        check_id=check_id,
        title="Anonymous write capability",
        severity=Severity.CRITICAL,
        target=TargetRef(
            url="https://x.example/arcgis/rest/services/Citizen/FeatureServer/0",
            kind=TargetKind.ARCGIS_LAYER,
            service_path="Citizen/FeatureServer",
            layer_id=0,
        ),
        description="FeatureServer accepts anonymous addFeatures.",
        evidence=Evidence(matched="Create,Update", notes=["capabilities=Query,Create,Update"]),
        remediation="Restrict editing to authenticated users.",
        references=["https://developers.arcgis.com/..."],
        cwe="CWE-862",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        kvkk_articles=["m12"],
        gdpr_articles=["art32", "art5-1-f"],
        tags=["anonymous", "write"],
        discovered_at=datetime(2026, 5, 3, tzinfo=UTC),
        scan_id="0123456789abcdef",
    )


class TestJsonWriter:
    def test_writes_stable_schema(self, tmp_path: Path) -> None:
        path = tmp_path / "report.json"
        JsonWriter(path).write([_finding()], _meta())
        data = json.loads(path.read_text())
        assert data["schema"] == SCHEMA_VERSION
        assert data["meta"]["scan_id"] == "0123456789abcdef"
        assert data["meta"]["counts_by_severity"]["critical"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["check_id"] == "ARC-002"
        assert data["findings"][0]["kvkk_articles"] == ["m12"]


class TestSarifWriter:
    def test_emits_valid_top_level_structure(self, tmp_path: Path) -> None:
        path = tmp_path / "report.sarif"
        SarifWriter(path).write([_finding()], _meta())
        sarif = json.loads(path.read_text())
        assert sarif["version"] == SARIF_VERSION
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "gisweep"
        assert sarif["runs"][0]["results"][0]["ruleId"] == "ARC-002"
        assert sarif["runs"][0]["results"][0]["level"] == "error"
        compliance = sarif["runs"][0]["results"][0]["properties"]["compliance"]
        assert compliance["kvkk"] == ["m12"]
        assert compliance["gdpr"] == ["art32", "art5-1-f"]


class TestMarkdownWriter:
    def test_renders_findings_with_compliance(self, tmp_path: Path) -> None:
        path = tmp_path / "report.md"
        MarkdownWriter(path).write([_finding()], _meta())
        text = path.read_text()
        assert "# gisweep scan report" in text
        assert "ARC-002" in text
        assert "KVKK m12" in text
        assert "GDPR art32" in text
        assert "Severity summary" in text


class TestHtmlWriter:
    def test_renders_self_contained_html(self, tmp_path: Path) -> None:
        path = tmp_path / "report.html"
        HtmlWriter(path).write([_finding()], _meta())
        html = path.read_text()
        assert html.startswith("<!doctype html>")
        assert "gisweep report" in html
        assert "ARC-002" in html
        assert "KVKK m12" in html
        assert "GDPR art32" in html
        assert "<style>" in html
        assert "<script" not in html  # zero JS, pure CSS


class TestRegistryParser:
    def test_extension_inference(self) -> None:
        spec = parse_output_arg("report.json")
        assert spec.format == "json"
        assert spec.path is not None and spec.path.name == "report.json"

    def test_explicit_format_path_form(self) -> None:
        spec = parse_output_arg("sarif:/tmp/out.sarif")
        assert spec.format == "sarif"

    def test_unknown_extension_raises(self) -> None:
        with pytest.raises(ValueError, match="cannot infer"):
            parse_output_arg("report.txt")

    def test_build_writer_roundtrip(self, tmp_path: Path) -> None:
        spec = parse_output_arg(str(tmp_path / "out.json"))
        writer = build_writer(spec)
        writer.write([_finding()], _meta())
        assert (tmp_path / "out.json").exists()
