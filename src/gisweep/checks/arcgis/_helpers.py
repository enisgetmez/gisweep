"""Shared helpers for ArcGIS check implementations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from gisweep.discovery.arcgis_enum import ArcGISEnumerator

if TYPE_CHECKING:
    from gisweep.core.context import Context


def cache_key(prefix: str, url: str) -> str:
    return f"{prefix}:{url}"


async def fetch_layer_info(ctx: Context, layer_url: str) -> dict[str, Any]:
    key = cache_key("arcgis_layer_info", layer_url)
    cached = ctx.cache.get(key)
    if isinstance(cached, dict):
        return cached
    enumerator = ArcGISEnumerator(ctx.http, layer_url)
    info = await enumerator.layer_info(layer_url)
    ctx.cache[key] = info
    return info


async def fetch_root_info(ctx: Context, root_url: str) -> dict[str, Any]:
    key = cache_key("arcgis_root_info", root_url)
    cached = ctx.cache.get(key)
    if isinstance(cached, dict):
        return cached
    enumerator = ArcGISEnumerator(ctx.http, root_url)
    info = await enumerator.root_info()
    ctx.cache[key] = info
    return info


def has_anonymous_token(ctx: Context) -> bool:
    auth = ctx.options.auth
    return not (auth and (auth.token or auth.username))
