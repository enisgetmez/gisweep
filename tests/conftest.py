"""Shared pytest fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gisweep.core import registry

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    """Each test runs against a clean registry, so decorator side effects
    declared in one test do not leak into another."""
    snapshot = list(registry.all_checks())
    snapshot_meta = {cls.meta.id: cls for cls in snapshot}
    registry.reset()
    yield
    registry.reset()
    for cls in snapshot_meta.values():
        registry._REGISTRY[cls.meta.id] = cls
