"""Unit tests for the runner skeleton."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
import structlog

from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.context import Context
from gisweep.core.finding import Evidence, Finding, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.registry import register
from gisweep.core.runner import Runner

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    pass


def _yield_finding(check_id: str, severity: Severity, target: TargetRef, scan_id: str) -> Finding:
    return Finding(
        check_id=check_id,
        title="probe",
        severity=severity,
        target=target,
        description="x",
        evidence=Evidence(),
        remediation="x",
        discovered_at=datetime.now(tz=UTC),
        scan_id=scan_id,
    )


def _passive_check(check_id: str, severity: Severity = Severity.LOW) -> type[Check]:
    @register(
        id=check_id,
        title=f"probe {check_id}",
        description="passive probe",
        category="test",
        severity=severity,
    )
    class _C(Check):
        async def run(
            self,
            target: TargetRef,
            ctx: Context,
        ) -> AsyncIterator[Finding]:
            yield _yield_finding(self.meta.id, self.meta.severity, target, ctx.scan_id)

    return _C


def _active_only_check(check_id: str) -> type[Check]:
    @register(
        id=check_id,
        title=f"active probe {check_id}",
        description="needs active",
        category="test",
        severity=Severity.HIGH,
        needs_active=True,
    )
    class _C(Check):
        async def run(
            self,
            target: TargetRef,
            ctx: Context,
        ) -> AsyncIterator[Finding]:
            yield _yield_finding(self.meta.id, self.meta.severity, target, ctx.scan_id)

    return _C


async def _build_ctx(options: ScanOptions, tmp_path: Path) -> Context:
    return Context(
        scan_id="scan-test",
        options=options,
        http=HttpClient(options),
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )


@pytest.mark.asyncio
async def test_runner_filters_active_only_in_passive_mode(tmp_path: Path) -> None:
    _passive_check("RUN-001")
    _active_only_check("RUN-002")
    ctx = await _build_ctx(ScanOptions(active=False), tmp_path)
    try:
        runner = Runner(ctx)
        targets = [TargetRef(url="https://x", kind=TargetKind.UNKNOWN)]
        findings, meta = await runner.run(targets)
        ids = {f.check_id for f in findings}
        assert ids == {"RUN-001"}
        assert meta.exit_code == 1
    finally:
        await ctx.http.aclose()


@pytest.mark.asyncio
async def test_runner_runs_active_check_when_active_flag_set(tmp_path: Path) -> None:
    _passive_check("RUN-003")
    _active_only_check("RUN-004")
    ctx = await _build_ctx(ScanOptions(active=True), tmp_path)
    try:
        runner = Runner(ctx)
        findings, _ = await runner.run([TargetRef(url="https://x", kind=TargetKind.UNKNOWN)])
        ids = {f.check_id for f in findings}
        assert ids == {"RUN-003", "RUN-004"}
    finally:
        await ctx.http.aclose()


@pytest.mark.asyncio
async def test_runner_respects_include_exclude(tmp_path: Path) -> None:
    _passive_check("RUN-005")
    _passive_check("RUN-006")
    _passive_check("RUN-007")
    ctx = await _build_ctx(
        ScanOptions(include=frozenset({"RUN-005", "RUN-007"}), exclude=frozenset({"RUN-007"})),
        tmp_path,
    )
    try:
        runner = Runner(ctx)
        findings, _ = await runner.run([TargetRef(url="https://x", kind=TargetKind.UNKNOWN)])
        assert {f.check_id for f in findings} == {"RUN-005"}
    finally:
        await ctx.http.aclose()


@pytest.mark.asyncio
async def test_runner_severity_threshold_filters(tmp_path: Path) -> None:
    _passive_check("RUN-008", severity=Severity.LOW)
    _passive_check("RUN-009", severity=Severity.CRITICAL)
    ctx = await _build_ctx(ScanOptions(severity_threshold=Severity.HIGH), tmp_path)
    try:
        runner = Runner(ctx)
        findings, meta = await runner.run([TargetRef(url="https://x", kind=TargetKind.UNKNOWN)])
        assert {f.check_id for f in findings} == {"RUN-009"}
        assert meta.counts_by_severity[Severity.CRITICAL] == 1
        assert meta.counts_by_severity[Severity.LOW] == 0
    finally:
        await ctx.http.aclose()


@pytest.mark.asyncio
async def test_runner_clean_scan_exit_zero(tmp_path: Path) -> None:
    ctx = await _build_ctx(ScanOptions(), tmp_path)
    try:
        runner = Runner(ctx)
        findings, meta = await runner.run([])
        assert findings == []
        assert meta.exit_code == 0
    finally:
        await ctx.http.aclose()
