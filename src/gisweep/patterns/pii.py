"""PII pattern matcher.

Loads :file:`src/gisweep/data/pii_patterns.yml` once at import time and exposes
helpers for testing field names, aliases, and (when sampled) values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class PiiPattern:
    id: str
    label: str
    name_regex: re.Pattern[str]
    value_regex: re.Pattern[str] | None
    kvkk: tuple[str, ...]
    gdpr: tuple[str, ...]
    sensitive: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PiiPattern:
        return cls(
            id=str(data["id"]),
            label=str(data["label"]),
            name_regex=re.compile(str(data["name_regex"]), re.IGNORECASE),
            value_regex=(re.compile(str(data["value_regex"])) if data.get("value_regex") else None),
            kvkk=tuple(str(x) for x in data.get("kvkk", [])),
            gdpr=tuple(str(x) for x in data.get("gdpr", [])),
            sensitive=bool(data.get("sensitive", False)),
        )


@dataclass(frozen=True, slots=True)
class PiiMatch:
    pattern: PiiPattern
    where: str  # "name" | "alias" | "value"
    matched: str


_NORMALIZE_RE = re.compile(r"[\W]+", flags=re.UNICODE)


def _normalize(value: str) -> str:
    """Collapse non-word separators to underscores so ``E-Posta``, ``e posta``,
    and ``e_posta`` all match the same regex alternative."""
    return _NORMALIZE_RE.sub("_", value)


@dataclass(frozen=True, slots=True)
class PiiMatcher:
    patterns: tuple[PiiPattern, ...] = field(default_factory=tuple)

    def match_field(self, name: str, alias: str = "") -> list[PiiMatch]:
        out: list[PiiMatch] = []
        norm_name = _normalize(name)
        norm_alias = _normalize(alias)
        for pattern in self.patterns:
            if name and pattern.name_regex.search(norm_name):
                out.append(PiiMatch(pattern=pattern, where="name", matched=name))
                continue
            if alias and pattern.name_regex.search(norm_alias):
                out.append(PiiMatch(pattern=pattern, where="alias", matched=alias))
        return out

    def match_value(self, value: str) -> list[PiiMatch]:
        out: list[PiiMatch] = []
        for pattern in self.patterns:
            if pattern.value_regex is None:
                continue
            m = pattern.value_regex.search(value)
            if m:
                out.append(PiiMatch(pattern=pattern, where="value", matched=m.group(0)))
        return out


@lru_cache(maxsize=1)
def get_pii_matcher() -> PiiMatcher:
    text = files("gisweep.data").joinpath("pii_patterns.yml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    if not isinstance(raw, list):
        raise ValueError("pii_patterns.yml must be a YAML list")
    return PiiMatcher(patterns=tuple(PiiPattern.from_dict(item) for item in raw))
