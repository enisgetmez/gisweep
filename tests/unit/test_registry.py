"""Unit tests for the check registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gisweep.core import Severity
from gisweep.core.check import Check
from gisweep.core.registry import (
    all_checks,
    all_meta,
    by_category,
    get_check,
    get_meta,
    register,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.core.finding import Finding, TargetRef


def _make_check(
    check_id: str,
    *,
    category: str = "test",
    severity: Severity = Severity.LOW,
) -> type[Check]:
    @register(
        id=check_id,
        title=f"Probe {check_id}",
        description="Test check.",
        category=category,
        severity=severity,
    )
    class _Probe(Check):
        async def run(
            self,
            target: TargetRef,
            ctx: Context,
        ) -> AsyncIterator[Finding]:
            return
            yield  # pragma: no cover -- empty async generator marker

    return _Probe


def test_register_attaches_meta() -> None:
    cls = _make_check("TEST-001")
    assert cls.meta.id == "TEST-001"
    assert cls.meta.title == "Probe TEST-001"
    assert cls.meta.severity == Severity.LOW


def test_get_meta_and_get_check() -> None:
    cls = _make_check("TEST-002")
    assert get_meta("TEST-002") == cls.meta
    assert get_check("TEST-002") is cls


def test_get_meta_unknown_returns_none() -> None:
    assert get_meta("DOES-NOT-EXIST") is None
    assert get_check("DOES-NOT-EXIST") is None


def test_all_meta_lists_registered_checks() -> None:
    _make_check("TEST-003")
    _make_check("TEST-004")
    ids = {m.id for m in all_meta()}
    assert {"TEST-003", "TEST-004"}.issubset(ids)


def test_all_checks_returns_classes() -> None:
    cls = _make_check("TEST-005")
    assert cls in all_checks()


def test_by_category_filters() -> None:
    _make_check("TEST-006", category="alpha")
    _make_check("TEST-007", category="beta")
    alphas = [m.id for m in by_category("alpha")]
    assert "TEST-006" in alphas
    assert "TEST-007" not in alphas


def test_duplicate_registration_raises() -> None:
    _make_check("TEST-008")
    with pytest.raises(ValueError, match="duplicate check id"):
        _make_check("TEST-008")
