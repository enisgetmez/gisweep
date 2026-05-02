"""Per-scan execution context passed into every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    import structlog

    from gisweep.core.http import HttpClient
    from gisweep.core.options import ScanOptions


@dataclass
class Context:
    scan_id: str
    options: ScanOptions
    http: HttpClient
    logger: structlog.stdlib.BoundLogger
    output_dir: Path
    cache: dict[str, Any] = field(default_factory=dict)
