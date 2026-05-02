"""Shared pytest fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gisweep.core import registry

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    """Snapshot built-in checks at session entry; restore them before each test
    so any test-only registrations that come and go cannot leak across tests
    while built-ins remain available everywhere."""
    snapshot = {cls.meta.id: cls for cls in registry.all_checks()}
    registry.reset()
    for cls in snapshot.values():
        registry._REGISTRY[cls.meta.id] = cls
    yield
    registry.reset()
    for cls in snapshot.values():
        registry._REGISTRY[cls.meta.id] = cls
