"""Single source of truth for the package version."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gisweep")
except PackageNotFoundError:
    __version__ = "0.0.0+local"
