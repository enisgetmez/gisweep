"""Secret pattern matcher (Google, AWS, GitHub, Stripe, JWT, ArcGIS token …).

Designed for low-FP detection: every pattern carries a vendor-specific prefix
and a length/charset constraint. Generic high-entropy heuristics are
intentionally absent — minified JS bundles produce too many false hits, and a
loud scanner gets ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml

from gisweep.core.finding import Severity


@dataclass(frozen=True, slots=True)
class SecretPattern:
    id: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    kvkk: tuple[str, ...]
    gdpr: tuple[str, ...]
    verifiable: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretPattern:
        sev_raw = str(data.get("severity") or "medium").lower()
        try:
            severity = Severity(sev_raw)
        except ValueError:
            severity = Severity.MEDIUM
        return cls(
            id=str(data["id"]),
            label=str(data["label"]),
            pattern=re.compile(str(data["pattern"])),
            severity=severity,
            kvkk=tuple(str(x) for x in data.get("kvkk") or ()),
            gdpr=tuple(str(x) for x in data.get("gdpr") or ()),
            verifiable=bool(data.get("verifiable", False)),
        )


@dataclass(frozen=True, slots=True)
class SecretMatch:
    pattern: SecretPattern
    matched: str  # the raw match — caller must redact before display
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class SecretMatcher:
    patterns: tuple[SecretPattern, ...] = field(default_factory=tuple)

    def scan(self, text: str) -> list[SecretMatch]:
        out: list[SecretMatch] = []
        for pattern in self.patterns:
            out.extend(
                SecretMatch(
                    pattern=pattern,
                    matched=m.group(0),
                    start=m.start(),
                    end=m.end(),
                )
                for m in pattern.pattern.finditer(text)
            )
        return out


def redact_secret(value: str) -> str:
    """Reduce a secret to its prefix + a four-char fingerprint of the suffix."""
    cleaned = value.strip()
    if len(cleaned) <= 8:  # noqa: PLR2004 -- short tokens are unsafe to surface
        return "***"
    head = cleaned[:4]
    tail = cleaned[-4:]
    return f"{head}…***{tail}"


@lru_cache(maxsize=1)
def get_secret_matcher() -> SecretMatcher:
    text = files("gisweep.data").joinpath("secret_patterns.yml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if not isinstance(raw, list):
        raise ValueError("secret_patterns.yml must be a YAML list")
    return SecretMatcher(patterns=tuple(SecretPattern.from_dict(item) for item in raw))
