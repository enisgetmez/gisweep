"""Stable-schema JSON report writer (``gisweep.report.v1``)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from gisweep.outputs._meta import meta_to_dict

if TYPE_CHECKING:
    from pathlib import Path

    from gisweep.core.finding import Finding
    from gisweep.core.runner import ScanMeta


SCHEMA_VERSION = "gisweep.report.v1"


class JsonWriter:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: list[Finding], meta: ScanMeta) -> None:
        payload = {
            "schema": SCHEMA_VERSION,
            "meta": meta_to_dict(meta),
            "findings": [json.loads(f.model_dump_json()) for f in findings],
        }
        self._path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False),
            encoding="utf-8",
        )
