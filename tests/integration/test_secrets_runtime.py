"""End-to-end integration test for the `gisweep secrets` subcommand."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from gisweep.cli import app

if TYPE_CHECKING:
    from pathlib import Path


def test_secrets_finds_google_api_key_in_local_dir(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "config.js").write_text(
        'export const GOOGLE_MAPS_API_KEY = "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVWX";\n',
        encoding="utf-8",
    )
    (src / "irrelevant.txt").write_text("nothing here\n", encoding="utf-8")

    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        ["secrets", str(src), "-o", str(out)],
        catch_exceptions=False,
    )
    assert result.exit_code == 1, result.stdout
    payload = json.loads(out.read_text())
    ids = [f["check_id"] for f in payload["findings"]]
    assert "SEC-001" in ids
    pattern_ids = {note for f in payload["findings"] for note in f["evidence"]["notes"]}
    assert any("google-maps-api-key" in note for note in pattern_ids)
    matched = next(f["evidence"]["matched"] for f in payload["findings"])
    assert "AIzaSyA1234567890ABCDEFGHIJKLMNOPQRSTUVWX" not in matched
    assert "***" in matched


def test_secrets_returns_zero_exit_on_clean_dir(tmp_path: Path) -> None:
    (tmp_path / "ok.js").write_text("// nothing sensitive\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["secrets", str(tmp_path)], catch_exceptions=False)
    assert result.exit_code == 0
