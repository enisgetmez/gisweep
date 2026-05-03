"""Async scan orchestrator."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from gisweep._version import __version__
from gisweep.core.finding import Finding, Severity
from gisweep.core.registry import all_checks

if TYPE_CHECKING:
    from collections.abc import Iterable

    from gisweep.core.check import Check
    from gisweep.core.context import Context
    from gisweep.core.finding import TargetRef


@dataclass(frozen=True, slots=True)
class ScanMeta:
    scan_id: str
    started_at: datetime
    finished_at: datetime
    targets: tuple[str, ...]
    gisweep_version: str
    exit_code: int
    counts_by_severity: dict[Severity, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CheckProgress:
    """Snapshot passed to a runner ``on_progress`` callback after each unit."""

    completed: int
    total: int
    check_id: str
    target_url: str


ProgressCallback = Callable[[CheckProgress], None]


class Runner:
    def __init__(self, ctx: Context, checks: Iterable[type[Check]] | None = None) -> None:
        self._ctx = ctx
        self._checks: list[type[Check]] = list(checks) if checks is not None else all_checks()
        self._log = structlog.get_logger(__name__).bind(scan_id=ctx.scan_id)

    def selected_checks(self) -> list[type[Check]]:
        opts = self._ctx.options
        result: list[type[Check]] = []
        for cls in self._checks:
            meta = cls.meta
            if opts.include and meta.id not in opts.include:
                continue
            if meta.id in opts.exclude:
                continue
            if meta.needs_active and not opts.active:
                continue
            result.append(cls)
        return result

    async def run(
        self,
        targets: Iterable[TargetRef],
        *,
        on_progress: ProgressCallback | None = None,
    ) -> tuple[list[Finding], ScanMeta]:
        targets_list = list(targets)
        started = datetime.now(tz=UTC)
        findings: list[Finding] = []

        selected = self.selected_checks()
        total_units = len(selected) * len(targets_list)
        self._log.info(
            "scan.started",
            target_count=len(targets_list),
            check_count=len(selected),
            active=self._ctx.options.active,
        )

        threshold = self._ctx.options.severity_threshold
        completed = 0
        for cls in selected:
            instance = cls()
            for target in targets_list:
                findings.extend(
                    [
                        f
                        async for f in instance.run(target, self._ctx)
                        if f.severity.at_least(threshold)
                    ]
                )
                completed += 1
                if on_progress is not None:
                    on_progress(
                        CheckProgress(
                            completed=completed,
                            total=total_units,
                            check_id=cls.meta.id,
                            target_url=target.url,
                        )
                    )

        finished = datetime.now(tz=UTC)
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in findings:
            counts[f.severity] += 1

        meta = ScanMeta(
            scan_id=self._ctx.scan_id,
            started_at=started,
            finished_at=finished,
            targets=tuple(t.url for t in targets_list),
            gisweep_version=__version__,
            exit_code=_compute_exit_code(findings, self._ctx.options.severity_threshold),
            counts_by_severity=counts,
        )
        self._log.info(
            "scan.finished",
            findings=len(findings),
            duration_s=(finished - started).total_seconds(),
        )
        return findings, meta


def _compute_exit_code(findings: list[Finding], threshold: Severity) -> int:
    return 1 if any(f.severity.at_least(threshold) for f in findings) else 0


# silence unused-import warning when running without checks loaded
_ = asyncio
