"""Output writers for findings (console, JSON, SARIF, HTML, Markdown)."""

from gisweep.outputs.base import OutputWriter
from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.html import HtmlWriter
from gisweep.outputs.json_writer import JsonWriter
from gisweep.outputs.markdown import MarkdownWriter
from gisweep.outputs.registry import OutputSpec, build_writer, parse_output_arg
from gisweep.outputs.sarif import SarifWriter

__all__ = [
    "ConsoleWriter",
    "HtmlWriter",
    "JsonWriter",
    "MarkdownWriter",
    "OutputSpec",
    "OutputWriter",
    "SarifWriter",
    "build_writer",
    "parse_output_arg",
]
