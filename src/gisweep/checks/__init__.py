"""Built-in check packages.

Importing :mod:`gisweep.checks` imports every check sub-package which, by side
effect of the ``@register`` decorator, populates the global registry.
"""

from gisweep.checks import arcgis, ogc, web  # noqa: F401
