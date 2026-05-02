"""Shared helpers for OGC check implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gisweep.discovery.ogc_enum import OgcCapabilities


CACHE_KEY = "ogc_capabilities"


def cached_capabilities(ctx: object) -> list[OgcCapabilities]:
    """Read the per-scan cache populated by the OGC runtime, falling back to
    an empty list when the runtime has not run yet (defensive)."""
    cache = getattr(ctx, "cache", None)
    if not isinstance(cache, dict):
        return []
    value = cache.get(CACHE_KEY)
    if not isinstance(value, list):
        return []
    return value
