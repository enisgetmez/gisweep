"""WFS feature-type schema discovery.

The capabilities document tells us *which* feature types exist; to learn
their **fields** we need to call ``DescribeFeatureType``. The OGC checks
that mirror ARC-014 (PII fields) and ARC-013/017 (unbounded query /
anonymous read) need this schema, so we factor it out as a small,
reusable helper backed by :mod:`defusedxml` and the shared async HTTP
client.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
from defusedxml import ElementTree as Det

if TYPE_CHECKING:
    from gisweep.core.context import Context


_HTTP_OK = 200
_GEOMETRY_TYPE_HINTS = ("gml:", "geometry", "point", "polygon", "linestring", "multi")


@dataclass(frozen=True, slots=True)
class WfsFieldRef:
    """A single attribute / field on a WFS feature type."""

    name: str
    type: str
    is_geometry: bool
    nullable: bool


@dataclass(frozen=True, slots=True)
class WfsFeatureSchema:
    """Schema view of a single WFS feature type."""

    type_name: str
    namespace: str
    geometry_property: str | None
    fields: tuple[WfsFieldRef, ...]


async def describe_feature_type(
    ctx: Context,
    endpoint: str,
    type_name: str,
    *,
    wfs_version: str = "2.0.0",
) -> WfsFeatureSchema | None:
    """Return the schema of *type_name* at *endpoint* via WFS DescribeFeatureType.

    Returns ``None`` when the request fails, the response is not parseable
    XML, or the schema does not declare any element children. We deliberately
    swallow network and parser errors — the caller treats absence of a
    schema as "skip this feature type" rather than "scan failed".
    """
    type_param = "TYPENAMES" if wfs_version.startswith("2") else "TYPENAME"
    params = {
        "SERVICE": "WFS",
        "VERSION": wfs_version,
        "REQUEST": "DescribeFeatureType",
        type_param: type_name,
    }
    try:
        response = await ctx.http.get(endpoint, params=params)
    except (httpx.HTTPError, OSError):
        return None
    if response.status_code != _HTTP_OK or not response.content:
        return None
    try:
        root = Det.fromstring(response.text)
    except (Det.ParseError, ValueError):
        return None

    namespace = root.attrib.get("targetNamespace") or ""
    fields: list[WfsFieldRef] = []
    geometry_property: str | None = None

    for element in root.iter():
        local = element.tag.split("}", 1)[1] if "}" in element.tag else element.tag
        if local != "element":
            continue
        name = element.attrib.get("name")
        type_attr = element.attrib.get("type", "")
        nillable = element.attrib.get("nillable", "false").lower() == "true"
        if not name:
            continue
        is_geom = any(hint in type_attr.lower() for hint in _GEOMETRY_TYPE_HINTS)
        if is_geom and geometry_property is None:
            geometry_property = name
        fields.append(
            WfsFieldRef(
                name=name,
                type=type_attr,
                is_geometry=is_geom,
                nullable=nillable,
            )
        )

    if not fields:
        return None
    return WfsFeatureSchema(
        type_name=type_name,
        namespace=namespace,
        geometry_property=geometry_property,
        fields=tuple(fields),
    )
