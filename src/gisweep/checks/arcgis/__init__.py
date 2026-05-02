"""ArcGIS-aware check implementations.

Every submodule registers its checks at import time via the ``@register``
decorator; importing this package therefore populates the global registry
with the ArcGIS catalogue.
"""

from gisweep.checks.arcgis import data, enumeration, permissions  # noqa: F401
