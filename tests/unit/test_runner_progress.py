"""Verify the runner ``on_progress`` callback fires once per (check, target)."""

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
from gisweep.core.runner import CheckProgress, Runner

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


def _yield_finding(check_id: str, target: TargetRef, scan_id: str) -> Finding:
    return Finding(
        check_id=check_id,
        title="probe",
        severity=Severity.LOW,
        target=target,
        description="x",
        evidence=Evidence(),
        remediation="x",
        discovered_at=datetime.now(tz=UTC),
        scan_id=scan_id,
    )


def _passive_check(check_id: str) -> type[Check]:
    @register(
        id=check_id,
        title=check_id,
        description="probe",
        category="test",
        severity=Severity.LOW,
    )
    class _C(Check):
        async def run(
            self,
            target: TargetRef,
            ctx: Context,
        ) -> AsyncIterator[Finding]:
            yield _yield_finding(check_id, target, ctx.scan_id)

    return _C


@pytest.mark.asyncio
async def test_progress_callback_fires_once_per_unit(tmp_path: Path) -> None:
    cls_a = _passive_check("PROG-001")
    cls_b = _passive_check("PROG-002")
    options = ScanOptions()
    http = HttpClient(options)
    ctx = Context(
        scan_id="scan-progress",
        options=options,
        http=http,
        logger=structlog.get_logger().bind(),
        output_dir=tmp_path,
    )
    try:
        runner = Runner(ctx, checks=[cls_a, cls_b])
        targets = [
            TargetRef(url=f"https://x.example/layer/{i}", kind=TargetKind.UNKNOWN) for i in range(3)
        ]
        events: list[CheckProgress] = []
        await runner.run(targets, on_progress=events.append)
        # 2 checks * 3 targets = 6 events
        assert len(events) == 6
        assert events[-1].completed == 6
        assert events[-1].total == 6
        # check_ids should cover both registered checks
        seen_checks = {ev.check_id for ev in events}
        assert seen_checks == {"PROG-001", "PROG-002"}
    finally:
        await http.aclose()
