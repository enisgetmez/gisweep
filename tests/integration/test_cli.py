"""End-to-end CLI smoke tests via Typer's CliRunner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from gisweep import _version
from gisweep.cli import app
from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.registry import register

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.core.finding import Finding, TargetRef


def _register_demo_check() -> None:
    @register(
        id="DEMO-001",
        title="Demo finding",
        description="A check used by CLI integration tests.",
        category="test",
        severity=Severity.MEDIUM,
        cwe="CWE-200",
        kvkk=("m12",),
        gdpr=("art32",),
        references=("https://example.com",),
    )
    class _Demo(Check):
        async def run(
            self,
            target: TargetRef,
            ctx: Context,
        ) -> AsyncIterator[Finding]:
            return
            yield  # pragma: no cover -- empty async generator marker


def test_version_command() -> None:
    result = CliRunner().invoke(app, ["version"])
    assert result.exit_code == 0
    assert _version.__version__ in result.stdout


def test_checks_list_empty_when_filtered_to_unknown_category() -> None:
    result = CliRunner().invoke(app, ["checks", "list", "--category", "unknown-cat"])
    assert result.exit_code == 0
    assert "No checks registered" in result.stdout


def test_checks_list_with_registered_check() -> None:
    _register_demo_check()
    result = CliRunner().invoke(app, ["checks", "list"])
    assert result.exit_code == 0
    assert "DEMO-001" in result.stdout
    assert "Demo finding" in result.stdout


def test_checks_list_filtered_by_category() -> None:
    _register_demo_check()
    result = CliRunner().invoke(app, ["checks", "list", "--category", "arcgis"])
    assert result.exit_code == 0
    assert "DEMO-001" not in result.stdout


def test_checks_info_unknown_id_exits_one() -> None:
    result = CliRunner().invoke(app, ["checks", "info", "NONEXISTENT-999"])
    assert result.exit_code == 1
    assert "Unknown check id" in result.stdout


def test_checks_info_known_id_renders_metadata() -> None:
    _register_demo_check()
    result = CliRunner().invoke(app, ["checks", "info", "DEMO-001"])
    assert result.exit_code == 0
    assert "DEMO-001" in result.stdout
    assert "Demo finding" in result.stdout
    assert "CWE-200" in result.stdout
    assert "m12" in result.stdout
    assert "art32" in result.stdout


def test_scan_stub_exits_two() -> None:
    """The auto-detect ``scan`` subcommand is the only remaining stub."""
    result = CliRunner().invoke(app, ["scan", "https://x.example"])
    assert result.exit_code == 2
