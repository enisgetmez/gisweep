"""Output writer protocol."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


@runtime_checkable
class OutputWriter(Protocol):
    def write(self, findings: list[Finding], meta: ScanMeta) -> None: ...
