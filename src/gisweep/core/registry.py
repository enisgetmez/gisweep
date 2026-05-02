"""Decorator-based check registry.

Each check class is decorated with ``@register(...)`` which validates the
metadata, attaches it to the class as ``cls.meta``, and indexes the class by
``id``. Catalogue listings (``gisweep checks list``) and SARIF rule emission
read from this single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

    from gisweep.core.check import Check
    from gisweep.core.finding import Severity


@dataclass(frozen=True, slots=True)
class CheckMeta:
    id: str
    title: str
    description: str
    category: str
    severity: Severity
    cwe: str | None = None
    cvss_vector: str | None = None
    kvkk: tuple[str, ...] = ()
    gdpr: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    needs_active: bool = False
    can_verify_active: bool = False
    target_kinds: tuple[str, ...] = ()


_REGISTRY: dict[str, type[Check]] = {}

C = TypeVar("C", bound="type[Check]")


def register(
    *,
    id: str,  # noqa: A002 -- ``id`` mirrors the public catalogue identifier
    title: str,
    description: str,
    category: str,
    severity: Severity,
    cwe: str | None = None,
    cvss_vector: str | None = None,
    kvkk: tuple[str, ...] = (),
    gdpr: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
    needs_active: bool = False,
    can_verify_active: bool = False,
    target_kinds: tuple[str, ...] = (),
) -> Callable[[C], C]:
    meta = CheckMeta(
        id=id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        cwe=cwe,
        cvss_vector=cvss_vector,
        kvkk=kvkk,
        gdpr=gdpr,
        references=references,
        tags=tags,
        needs_active=needs_active,
        can_verify_active=can_verify_active,
        target_kinds=target_kinds,
    )

    def decorator(cls: C) -> C:
        if meta.id in _REGISTRY:
            raise ValueError(f"duplicate check id: {meta.id!r}")
        cls.meta = meta
        _REGISTRY[meta.id] = cls
        return cls

    return decorator


def get_meta(check_id: str) -> CheckMeta | None:
    cls = _REGISTRY.get(check_id)
    return cls.meta if cls is not None else None


def get_check(check_id: str) -> type[Check] | None:
    return _REGISTRY.get(check_id)


def all_meta() -> list[CheckMeta]:
    return [cls.meta for cls in _REGISTRY.values()]


def all_checks() -> list[type[Check]]:
    return list(_REGISTRY.values())


def by_category(category: str) -> list[CheckMeta]:
    return [m for m in all_meta() if m.category == category]


def reset() -> None:
    """Test helper — wipes the registry. Do not use at runtime."""
    _REGISTRY.clear()


# late import to avoid the circular form when someone does ``from gisweep.core
# import register`` before any check module is imported
