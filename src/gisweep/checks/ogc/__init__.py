"""OGC web service check implementations (WMS / WFS over GeoServer, MapServer, QGIS Server, …)."""

from gisweep.checks.ogc import (  # noqa: F401
    active,
    capabilities,
    cves,
    data,
    permissions,
)
