"""Output writers for findings (console, JSON, SARIF, HTML, Markdown)."""

from gisweep.outputs.base import OutputWriter
from gisweep.outputs.console import ConsoleWriter

__all__ = ["ConsoleWriter", "OutputWriter"]
