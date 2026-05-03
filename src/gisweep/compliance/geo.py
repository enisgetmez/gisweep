"""Country-code lookup for KVKK / GDPR cross-border transfer checks.

The hostname → country mapping is delegated to ``ipapi.co/<hostname>/country``,
a free service with a generous unauthenticated rate limit. Results are cached
per scan so a single run never resolves the same host twice. When the lookup
fails (DNS error, rate limited, network blocked), the helper returns ``None``
and COMP-002 silently skips the host — false negatives are preferred over
false positives that would force operators to ignore the check.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING

import httpx
import yaml

if TYPE_CHECKING:
    from gisweep.core.http import HttpClient


_GEO_API = "https://ipapi.co"
_HTTP_OK = 200


@lru_cache(maxsize=1)
def safe_country_codes() -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(kvkk_safe, gdpr_safe)`` from the bundled YAML."""
    text = files("gisweep.data").joinpath("country_codes.yml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    kvkk = frozenset(str(c).upper() for c in data.get("kvkk_safe", []))
    gdpr = frozenset(str(c).upper() for c in data.get("gdpr_safe", []))
    return kvkk, gdpr


async def lookup_country(
    http: HttpClient,
    host: str,
    *,
    cache: dict[str, str | None] | None = None,
) -> str | None:
    """Resolve a host to its ISO 3166-1 alpha-2 country code, or ``None``."""
    if cache is not None and host in cache:
        return cache[host]
    url = f"{_GEO_API}/{host}/country"
    code: str | None = None
    try:
        response = await http.get(url)
        if response.status_code == _HTTP_OK and response.content:
            text = response.text.strip().upper()
            if len(text) == 2 and text.isalpha():  # noqa: PLR2004
                code = text
    except (httpx.HTTPError, OSError):
        code = None
    if cache is not None:
        cache[host] = code
    return code
