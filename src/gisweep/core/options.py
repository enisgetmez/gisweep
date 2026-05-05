"""Scan-time options carried through the runner into every check."""

from __future__ import annotations

from dataclasses import dataclass, field

from gisweep.core.finding import Severity


@dataclass(frozen=True, slots=True)
class AuthConfig:
    token: str | None = None
    username: str | None = None
    password: str | None = None
    portal_url: str | None = None
    referer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


@dataclass(frozen=True, slots=True)
class ScanOptions:
    active: bool = False
    i_own_this_target: bool = False
    auth_bruteforce: bool = False
    ssrf_canary: str | None = None
    proxy: str | None = None
    rate_limit: float | None = None
    timeout: float = 30.0
    max_concurrency: int = 10
    severity_threshold: Severity = Severity.INFO
    include: frozenset[str] = field(default_factory=frozenset)
    exclude: frozenset[str] = field(default_factory=frozenset)
    auth: AuthConfig | None = None
    user_agent: str = "gisweep/0.2.0 (+https://github.com/enisgetmez/gisweep)"
    verify_tls: bool = True
    # When False (default) any matched secret is reduced to "AIza…***xyz4"
    # before it lands in Evidence.matched / console / report files. Operators
    # who explicitly accept the operational risk can flip this to True via the
    # CLI's ``--show-secrets`` flag.
    show_secrets: bool = False
