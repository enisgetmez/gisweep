"""Standalone secrets scan runtime.

Drives the ``gisweep secrets <url-or-path>`` subcommand: fetches a remote
URL or walks a local file/directory, scans every text body against the
secret pattern catalogue, and emits one ``SEC-001`` finding per hit.
Reuses the standard output writers and compliance overlay so reports
look identical to the ArcGIS / OGC runtimes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import structlog

from gisweep import _version
from gisweep.compliance import apply_overlay
from gisweep.core.finding import Evidence, Finding, Severity, TargetKind, TargetRef
from gisweep.core.http import HttpClient
from gisweep.core.options import ScanOptions
from gisweep.core.runner import ScanMeta
from gisweep.outputs.console import ConsoleWriter
from gisweep.outputs.registry import build_writer, parse_output_arg
from gisweep.patterns.secrets import (
    SecretMatch,
    SecretMatcher,
    get_secret_matcher,
    redact_secret,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from rich.console import Console


_TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".html",
        ".htm",
        ".css",
        ".json",
        ".xml",
        ".yml",
        ".yaml",
        ".env",
        ".txt",
        ".md",
        ".py",
    }
)
_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB sanity cap


@dataclass(frozen=True, slots=True)
class ScanRequest:
    target: str
    scan_id: str
    output_dir: Path
    outputs: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.INFO
    include: frozenset[str] = field(default_factory=frozenset)
    exclude: frozenset[str] = field(default_factory=frozenset)
    proxy: str | None = None
    rate_limit: float | None = None
    timeout: float = 30.0
    max_concurrency: int = 4
    verify_tls: bool = True


async def run(request: ScanRequest, *, console: Console | None = None) -> int:
    log = structlog.get_logger("gisweep.runtime.secrets").bind(scan_id=request.scan_id)
    matcher = get_secret_matcher()
    started = datetime.now(tz=UTC)

    findings: list[Finding] = []
    sources: list[str] = []
    target_path = _expand_path(request.target)
    if _path_exists(target_path):
        for path, content in _iter_local(target_path):
            sources.append(str(path))
            findings.extend(
                _to_findings(matcher, content, source=str(path), scan_id=request.scan_id)
            )
    else:
        options = ScanOptions(
            timeout=request.timeout,
            proxy=request.proxy,
            max_concurrency=request.max_concurrency,
            rate_limit=request.rate_limit,
            verify_tls=request.verify_tls,
        )
        async with HttpClient(options) as http:
            sources.append(request.target)
            try:
                response = await http.get(request.target)
            except (httpx.HTTPError, OSError) as exc:
                log.warning("secrets.fetch_failed", url=request.target, error=str(exc))
                return 2
            findings.extend(
                _to_findings(matcher, response.text, source=request.target, scan_id=request.scan_id)
            )

    findings = [f for f in findings if f.severity.at_least(request.severity_threshold)]
    if request.include:
        findings = [f for f in findings if f.check_id in request.include]
    if request.exclude:
        findings = [f for f in findings if f.check_id not in request.exclude]
    findings = apply_overlay(findings, scan_id=request.scan_id)

    finished = datetime.now(tz=UTC)
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] += 1
    exit_code = (
        1
        if any(counts[s] for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL))
        else 0
    )
    meta = ScanMeta(
        scan_id=request.scan_id,
        started_at=started,
        finished_at=finished,
        targets=tuple(sources),
        gisweep_version=_version.__version__,
        exit_code=exit_code,
        counts_by_severity=counts,
    )
    _emit_outputs(findings, meta, request.outputs, console)
    return exit_code


def _to_findings(
    matcher: SecretMatcher,
    content: str,
    *,
    source: str,
    scan_id: str,
) -> list[Finding]:
    return [_to_finding(match, source=source, scan_id=scan_id) for match in matcher.scan(content)]


def _to_finding(match: SecretMatch, *, source: str, scan_id: str) -> Finding:
    pattern = match.pattern
    return Finding(
        check_id="SEC-001",
        title=f"{pattern.label} leaked in source",
        severity=pattern.severity,
        target=TargetRef(url=source, kind=TargetKind.ASSET),
        description=(
            f"`{source}` contains a value matching the {pattern.label} pattern. "
            "Rotate the credential immediately and remove it from version control / "
            "served bundles. Hardcoded secrets in client-side bundles are equivalent "
            "to publishing them."
        ),
        evidence=Evidence(
            matched=redact_secret(match.matched),
            notes=[
                f"pattern_id={pattern.id}",
                f"offset={match.start}-{match.end}",
                f"verifiable={pattern.verifiable}",
            ],
        ),
        remediation=(
            "Revoke the leaked credential at its issuer (Google Cloud, AWS IAM, "
            "GitHub, Stripe, …), rotate every dependent system, and audit access "
            "logs for the exposure window. Then move the credential to an "
            "environment variable or secrets manager that never reaches the "
            "client tier."
        ),
        references=[],
        cwe="CWE-798",
        kvkk_articles=list(pattern.kvkk),
        gdpr_articles=list(pattern.gdpr),
        tags=["secret-leak", pattern.id],
        discovered_at=datetime.now(tz=UTC),
        scan_id=scan_id,
    )


def _expand_path(value: str) -> Path:
    return Path(value).expanduser()


def _path_exists(path: Path) -> bool:
    return path.exists()


def _iter_local(root: Path) -> Iterable[tuple[Path, str]]:
    if root.is_file():
        text = _safe_read(root)
        if text is not None:
            yield root, text
        return
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        text = _safe_read(path)
        if text is not None:
            yield path, text


def _safe_read(path: Path) -> str | None:
    if path.suffix.lower() not in _TEXT_SUFFIXES:
        return None
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _emit_outputs(
    findings: Sequence[Finding],
    meta: ScanMeta,
    output_args: Sequence[str],
    console: Console | None,
) -> None:
    findings_list = list(findings)
    ConsoleWriter(console).write(findings_list, meta)
    for arg in output_args:
        spec = parse_output_arg(arg)
        writer = build_writer(spec)
        writer.write(findings_list, meta)
