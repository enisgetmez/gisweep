"""Shared helpers for ArcGIS check implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

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
    token = ctx.cache.get("arcgis_token")
    enumerator = ArcGISEnumerator(ctx.http, layer_url, token=token)
    info = await enumerator.layer_info(layer_url)
    ctx.cache[key] = info
    return info


async def fetch_root_info(ctx: Context, root_url: str) -> dict[str, Any]:
    key = cache_key("arcgis_root_info", root_url)
    cached = ctx.cache.get(key)
    if isinstance(cached, dict):
        return cached
    token = ctx.cache.get("arcgis_token")
    enumerator = ArcGISEnumerator(ctx.http, root_url, token=token)
    info = await enumerator.root_info()
    ctx.cache[key] = info
    return info


def has_anonymous_token(ctx: Context) -> bool:
    auth = ctx.options.auth
    return not (auth and (auth.token or auth.username))


@dataclass(frozen=True, slots=True)
class LayerAccessProbe:
    """Outcome of an anonymous read probe against a single ArcGIS layer.

    The probe issues ``query?where=1=1&returnCountOnly=true&f=json`` — a pure
    read operation that does not mutate remote state, so it is safe to run
    in passive mode. ``confirmed_anonymous_read`` is true only when a 200
    response carries an integer ``count`` and no embedded ``error`` payload.
    """

    layer_url: str
    status_code: int | None
    count: int | None
    confirmed_anonymous_read: bool
    requires_auth: bool
    error: str | None = None


_HTTP_OK = 200
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403


async def probe_layer_query(ctx: Context, layer_url: str) -> LayerAccessProbe:
    """Probe a layer's read access. Result is cached per scan."""
    key = cache_key("arcgis_layer_probe", layer_url)
    cached = ctx.cache.get(key)
    if isinstance(cached, LayerAccessProbe):
        return cached

    token = ctx.cache.get("arcgis_token")
    enumerator = ArcGISEnumerator(ctx.http, layer_url, token=token)
    url = enumerator.with_query(
        f"{layer_url.rstrip('/')}/query",
        where="1=1",
        returnCountOnly="true",
    )
    try:
        response = await ctx.http.get(url)
    except (httpx.HTTPError, OSError) as exc:
        probe = LayerAccessProbe(
            layer_url=layer_url,
            status_code=None,
            count=None,
            confirmed_anonymous_read=False,
            requires_auth=False,
            error=str(exc),
        )
        ctx.cache[key] = probe
        return probe

    status = response.status_code
    requires_auth = status in {_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}
    count: int | None = None
    error_message: str | None = None

    if status == _HTTP_OK:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            embedded_error = payload.get("error")
            if isinstance(embedded_error, dict):
                code = embedded_error.get("code")
                error_message = str(embedded_error.get("message") or embedded_error)
                if code in {_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}:
                    requires_auth = True
            elif isinstance(payload.get("count"), int):
                count = int(payload["count"])

    probe = LayerAccessProbe(
        layer_url=layer_url,
        status_code=status,
        count=count,
        confirmed_anonymous_read=(count is not None),
        requires_auth=requires_auth,
        error=error_message,
    )
    ctx.cache[key] = probe
    return probe
