"""Integration test for runtime/web.py with a mocked BrowserCrawler."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

from typer.testing import CliRunner

from gisweep.cli import app
from gisweep.discovery.browser import (
    CapturedRequest,
    CapturedResponseBody,
    WebDiscoveryResult,
)
from gisweep.discovery.library_detect import DetectedLibrary

if TYPE_CHECKING:
    from pathlib import Path


def _result(*, html: str = "<html></html>") -> WebDiscoveryResult:
    return WebDiscoveryResult(
        page_url="https://demo.example/map",
        final_url="https://demo.example/map",
        requests=[
            CapturedRequest(
                url="https://x.gov/arcgis/rest/services/Foo/MapServer",
                method="GET",
                resource_type="xhr",
                response_status=200,
                response_headers=(),
            ),
        ],
        libraries=[DetectedLibrary("leaflet", "1.6.0", "global", "L.version=1.6.0")],
        bodies=[
            CapturedResponseBody(
                url="https://demo.example/static/app.js",
                resource_type="script",
                body='const KEY = "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVWX";',
            )
        ],
        page_html=html,
    )


def test_web_subcommand_writes_json_with_findings(tmp_path: Path) -> None:
    out = tmp_path / "report.json"

    async def _crawl_stub(self: object, url: str) -> WebDiscoveryResult:
        return _result()

    with patch(
        "gisweep.discovery.browser.BrowserCrawler.crawl",
        new=_crawl_stub,
    ):
        result = CliRunner().invoke(
            app,
            ["web", "https://demo.example/map", "-o", str(out)],
            catch_exceptions=False,
        )

    assert result.exit_code == 1, result.stdout
    payload = json.loads(out.read_text())
    ids = {f["check_id"] for f in payload["findings"]}
    assert "WEB-001" in ids  # endpoint inventory
    assert "WEB-002" in ids  # secret leaked


def test_web_subcommand_clean_page_exits_zero(tmp_path: Path) -> None:
    async def _crawl_clean(self: object, url: str) -> WebDiscoveryResult:
        return WebDiscoveryResult(
            page_url=url,
            final_url=url,
            requests=[],
            libraries=[],
            bodies=[],
            page_html="<html><body>nothing here</body></html>",
        )

    with patch("gisweep.discovery.browser.BrowserCrawler.crawl", new=_crawl_clean):
        result = CliRunner().invoke(
            app, ["web", "https://demo.example/clean"], catch_exceptions=False
        )
    assert result.exit_code == 0
