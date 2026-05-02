"""Built-in check packages.

Importing :mod:`gisweep.checks` imports every check sub-package which, by side
effect of the ``@register`` decorator, populates the global registry. Phase 1
ships an empty catalogue; concrete checks land in Phase 2.
"""

# Sub-package imports go here as checks are added in subsequent phases.
# Examples (Phase 2+):
#   from gisweep.checks import arcgis
#   from gisweep.checks import web
