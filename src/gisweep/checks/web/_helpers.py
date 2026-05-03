"""Shared helpers for WEB checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gisweep.discovery.browser import WebDiscoveryResult

CACHE_KEY = "web_discovery_result"


def cached_discovery(ctx: object) -> WebDiscoveryResult | None:
    cache = getattr(ctx, "cache", None)
    if not isinstance(cache, dict):
        return None
    from gisweep.discovery.browser import WebDiscoveryResult  # noqa: PLC0415

    value = cache.get(CACHE_KEY)
    if isinstance(value, WebDiscoveryResult):
        return value
    return None
