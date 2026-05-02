"""Output writer registry and ``-o`` argument parser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.html import HtmlWriter
from gisweep.outputs.json_writer import JsonWriter
from gisweep.outputs.markdown import MarkdownWriter
from gisweep.outputs.sarif import SarifWriter

if TYPE_CHECKING:
    from gisweep.outputs.base import OutputWriter


_EXTENSION_FORMAT: dict[str, str] = {
    ".json": "json",
    ".sarif": "sarif",
    ".sarif.json": "sarif",
    ".md": "markdown",
    ".markdown": "markdown",
    ".html": "html",
    ".htm": "html",
}


@dataclass(frozen=True, slots=True)
class OutputSpec:
    format: str
    path: Path | None  # None == stdout (only valid for ``console``)


def parse_output_arg(arg: str) -> OutputSpec:
    """Parse a single ``-o`` value such as ``report.json`` or ``json:report.json``."""
    if ":" in arg and not _looks_like_path(arg.split(":", 1)[0]):
        fmt_explicit, _, path_str = arg.partition(":")
        return OutputSpec(format=fmt_explicit.lower(), path=Path(path_str))

    path = Path(arg)
    suffix = "".join(path.suffixes).lower() if path.suffixes else ""
    fmt_inferred = _EXTENSION_FORMAT.get(suffix) or _EXTENSION_FORMAT.get(path.suffix.lower())
    if fmt_inferred is None:
        raise ValueError(
            f"cannot infer output format from {arg!r}; "
            "use 'json:path', 'sarif:path', 'markdown:path', or 'html:path'"
        )
    return OutputSpec(format=fmt_inferred, path=path)


def build_writer(spec: OutputSpec) -> OutputWriter:
    if spec.format == "console":
        return ConsoleWriter()
    if spec.path is None:
        raise ValueError(f"format {spec.format!r} requires a file path")
    if spec.format == "json":
        return JsonWriter(spec.path)
    if spec.format == "sarif":
        return SarifWriter(spec.path)
    if spec.format == "markdown":
        return MarkdownWriter(spec.path)
    if spec.format == "html":
        return HtmlWriter(spec.path)
    raise ValueError(f"unknown output format: {spec.format!r}")


def _looks_like_path(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.endswith((".json", ".sarif", ".md", ".markdown", ".html", ".htm"))
    )
