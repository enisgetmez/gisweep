"""Core primitives: findings, registry, runner, http, options."""

from gisweep.core.check import Check
from gisweep.core.context import Context
from gisweep.core.finding import (
    Evidence,
    Finding,
    HttpRequestSummary,
    HttpResponseSummary,
    Severity,
    TargetKind,
    TargetRef,
)
from gisweep.core.options import AuthConfig, ScanOptions
from gisweep.core.registry import CheckMeta, all_meta, get_meta, register

__all__ = [
    "AuthConfig",
    "Check",
    "CheckMeta",
    "Context",
    "Evidence",
    "Finding",
    "HttpRequestSummary",
    "HttpResponseSummary",
    "ScanOptions",
    "Severity",
    "TargetKind",
    "TargetRef",
    "all_meta",
    "get_meta",
    "register",
]
