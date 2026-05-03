"""Integration tests that exercise the discovery / scan summary lines emitted
by every runtime so the Phase-6.1 / 6.2 visibility fixes are locked in."""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
import respx
from httpx import Response
from rich.console import Console

from gisweep.discovery.browser import (
    CapturedRequest,
    CapturedResponseBody,
    WebDiscoveryResult,
)
from gisweep.discovery.library_detect import DetectedLibrary
from gisweep.runtime import auto as auto_runtime
from gisweep.runtime import ogc as ogc_runtime
from gisweep.runtime import secrets as secrets_runtime
from gisweep.runtime import web as web_runtime

if TYPE_CHECKING:
    from pathlib import Path


def _console() -> tuple[Console, StringIO]:
    buf = StringIO()
    return Console(file=buf, force_terminal=False, width=200), buf


@pytest.mark.asyncio
@respx.mock
async def test_ogc_runtime_emits_zero_capabilities_warning(tmp_path: Path) -> None:
    base = "https://gs.example/wat"
    respx.get(url__regex=r"https://gs\.example/.*").mock(return_value=Response(404))
    console, buf = _console()
    request = ogc_runtime.ScanRequest(url=base, scan_id="x", output_dir=tmp_path, outputs=())
    code = await ogc_runtime.run(request, console=console)
    assert code == 2
    out = buf.getvalue()
    assert "No WMS / WFS GetCapabilities" in out


@pytest.mark.asyncio
async def test_web_runtime_emits_crawl_summary(tmp_path: Path) -> None:
    async def _crawl_stub(self: object, url: str) -> WebDiscoveryResult:
        return WebDiscoveryResult(
            page_url=url,
            final_url=url,
            requests=[
                CapturedRequest(
                    url="https://demo.example/static/app.js",
                    method="GET",
                    resource_type="script",
                    response_status=200,
                    response_headers=(),
                ),
            ],
            libraries=[DetectedLibrary("leaflet", "1.9.4", "global", "L.version=1.9.4")],
            bodies=[
                CapturedResponseBody(
                    url="https://demo.example/static/app.js",
                    resource_type="script",
                    body="// nothing sensitive",
                )
            ],
            page_html="<html></html>",
        )

    console, buf = _console()
    request = web_runtime.ScanRequest(url="https://demo.example", scan_id="x", output_dir=tmp_path)
    with patch("gisweep.discovery.browser.BrowserCrawler.crawl", new=_crawl_stub):
        await web_runtime.run(request, console=console)
    out = buf.getvalue()
    assert "Loading" in out
    assert "leaflet=1.9.4" in out
    assert "Captured" in out


@pytest.mark.asyncio
async def test_secrets_runtime_emits_no_files_warning(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    console, buf = _console()
    request = secrets_runtime.ScanRequest(target=str(empty), scan_id="x", output_dir=tmp_path)
    await secrets_runtime.run(request, console=console)
    assert "No text-suffix files found" in buf.getvalue()


@pytest.mark.asyncio
async def test_secrets_runtime_emits_scan_count_summary(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.js").write_text("// nothing\n", encoding="utf-8")
    console, buf = _console()
    request = secrets_runtime.ScanRequest(target=str(src), scan_id="x", output_dir=tmp_path)
    await secrets_runtime.run(request, console=console)
    out = buf.getvalue()
    assert "Scanned" in out
    assert "1" in out


@pytest.mark.asyncio
@respx.mock
async def test_auto_runtime_prints_detected_kind(tmp_path: Path) -> None:
    url = "https://opaque.example/services"
    respx.get(url).mock(
        return_value=Response(
            200,
            json={"currentVersion": 11.2, "services": []},
            headers={"Content-Type": "application/json"},
        )
    )
    # arcgis_runtime.run will attempt the real walker; mock it via patch so we
    # don't need to set up the full target tree
    captured: dict[str, object] = {}

    async def _arcgis_stub(req: object, *, console: object = None) -> int:
        captured["dispatched"] = True
        return 0

    console, buf = _console()
    request = auto_runtime.DispatchRequest(
        url=url,
        scan_id="x",
        output_dir=tmp_path,
        outputs=(),
        timeout=10.0,
        verify_tls=True,
    )
    with patch("gisweep.runtime.arcgis.run", new=_arcgis_stub):
        await auto_runtime.run(request, console=console)
    assert captured.get("dispatched") is True
    assert "Auto-detected target as arcgis" in buf.getvalue()


@pytest.mark.asyncio
@respx.mock
async def test_auto_runtime_warns_on_unknown(tmp_path: Path) -> None:
    url = "https://opaque.example/binary"
    respx.get(url).mock(
        return_value=Response(
            200, content=b"\x00\x01\x02", headers={"Content-Type": "application/octet-stream"}
        )
    )
    console, buf = _console()
    request = auto_runtime.DispatchRequest(
        url=url,
        scan_id="x",
        output_dir=tmp_path,
        outputs=(),
        timeout=10.0,
        verify_tls=True,
    )
    code = await auto_runtime.run(request, console=console)
    assert code == 2
    assert "Could not determine the kind" in buf.getvalue()
