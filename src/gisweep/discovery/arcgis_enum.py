"""ArcGIS REST service walker.

Given a root URL of the form ``https://server/arcgis/rest/services``, walks the
folder tree, enumerates services, and for FeatureServer/MapServer services
introspects each layer to surface fields and capabilities. The discovered
hierarchy is what the rest of the scanner runs checks against.

All requests are GETs with ``f=json``; nothing here mutates remote state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlsplit, urlunsplit

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.http import HttpClient

_DEFAULT_MAX_DEPTH = 5
_LAYER_BEARING_TYPES: frozenset[str] = frozenset(
    {"FeatureServer", "MapServer", "ImageServer", "VectorTileServer"}
)


@dataclass(frozen=True, slots=True)
class ArcGISFieldRef:
    name: str
    alias: str
    type: str
    length: int | None = None


@dataclass(frozen=True, slots=True)
class ArcGISLayerRef:
    service_url: str
    layer_id: int
    name: str
    geometry_type: str | None
    capabilities: frozenset[str]
    fields: tuple[ArcGISFieldRef, ...]
    url: str
    has_attachments: bool = False
    max_record_count: int | None = None


@dataclass(frozen=True, slots=True)
class ArcGISServiceRef:
    name: str
    type: str
    folder: str | None
    url: str
    capabilities: frozenset[str] = field(default_factory=frozenset)


class ArcGISEnumerator:
    def __init__(
        self,
        http: HttpClient,
        root_url: str,
        *,
        token: str | None = None,
    ) -> None:
        self._http = http
        self._root = root_url.rstrip("/")
        self._token = token

    @property
    def root_url(self) -> str:
        return self._root

    def with_query(self, url: str, **extra: str) -> str:
        params: dict[str, str] = {"f": "json", **extra}
        if self._token is not None:
            params["token"] = self._token
        split = urlsplit(url)
        return urlunsplit(
            (split.scheme, split.netloc, split.path, urlencode(params), split.fragment)
        )

    async def root_info(self) -> dict[str, Any]:
        return await self._fetch_json(self._root)

    async def folder_info(self, folder: str) -> dict[str, Any]:
        return await self._fetch_json(f"{self._root}/{folder}")

    async def service_info(self, service: ArcGISServiceRef) -> dict[str, Any]:
        return await self._fetch_json(service.url)

    async def layer_info(self, layer_url: str) -> dict[str, Any]:
        return await self._fetch_json(layer_url)

    async def walk(self, max_depth: int = _DEFAULT_MAX_DEPTH) -> AsyncIterator[ArcGISServiceRef]:
        """Yield every service reachable from the root, recursing into folders."""
        async for svc in self._walk_folder(folder=None, depth=0, max_depth=max_depth):
            yield svc

    async def layers(self, service: ArcGISServiceRef) -> AsyncIterator[ArcGISLayerRef]:
        if service.type not in _LAYER_BEARING_TYPES:
            return
        info = await self.service_info(service)
        for spec in info.get("layers") or []:
            layer_id = spec.get("id")
            if layer_id is None:
                continue
            layer_url = f"{service.url}/{layer_id}"
            yield await self._build_layer_ref(service.url, layer_id, layer_url)
        for spec in info.get("tables") or []:
            table_id = spec.get("id")
            if table_id is None:
                continue
            table_url = f"{service.url}/{table_id}"
            yield await self._build_layer_ref(service.url, table_id, table_url)

    async def _walk_folder(
        self,
        folder: str | None,
        depth: int,
        max_depth: int,
    ) -> AsyncIterator[ArcGISServiceRef]:
        if depth > max_depth:
            return
        info = await self.root_info() if folder is None else await self.folder_info(folder)
        for service in info.get("services") or []:
            name = service.get("name")
            stype = service.get("type")
            if not name or not stype:
                continue
            short = name.split("/")[-1]
            url = f"{self._root}/{name}/{stype}"
            yield ArcGISServiceRef(
                name=short,
                type=stype,
                folder=folder,
                url=url,
                capabilities=_parse_capabilities(service),
            )
        for child in info.get("folders") or []:
            qualified = f"{folder}/{child}" if folder else child
            async for svc in self._walk_folder(qualified, depth + 1, max_depth):
                yield svc

    async def _build_layer_ref(
        self,
        service_url: str,
        layer_id: int,
        layer_url: str,
    ) -> ArcGISLayerRef:
        info = await self.layer_info(layer_url)
        return ArcGISLayerRef(
            service_url=service_url,
            layer_id=layer_id,
            name=str(info.get("name") or f"layer_{layer_id}"),
            geometry_type=info.get("geometryType"),
            capabilities=_parse_capabilities(info),
            fields=tuple(
                ArcGISFieldRef(
                    name=str(f.get("name") or ""),
                    alias=str(f.get("alias") or ""),
                    type=str(f.get("type") or ""),
                    length=f.get("length"),
                )
                for f in (info.get("fields") or [])
                if f.get("name")
            ),
            url=layer_url,
            has_attachments=bool(info.get("hasAttachments")),
            max_record_count=info.get("maxRecordCount"),
        )

    async def _fetch_json(self, base_url: str) -> dict[str, Any]:
        url = self.with_query(base_url)
        response = await self._http.get(url)
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError:
            # Some misconfigured servers return HTML (or empty) at REST paths
            # despite ``f=json``; treat as "nothing here" so the walker can
            # keep going instead of aborting the whole scan.
            return {}
        if not isinstance(data, dict):
            return {}
        return data


def _parse_capabilities(info: dict[str, Any]) -> frozenset[str]:
    raw = info.get("capabilities") or ""
    if isinstance(raw, list):
        return frozenset(str(item).strip() for item in raw if item)
    return frozenset(part.strip() for part in str(raw).split(",") if part.strip())
