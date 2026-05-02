"""Check abstract base class.

A concrete check subclasses ``Check``, decorates itself with ``@register(...)``
to attach its ``CheckMeta``, and implements ``run`` as an async generator
yielding ``Finding`` instances.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from gisweep.core.context import Context
    from gisweep.core.finding import Finding, TargetRef
    from gisweep.core.registry import CheckMeta


class Check(ABC):
    meta: ClassVar[CheckMeta]

    @abstractmethod
    def run(
        self,
        target: TargetRef,
        ctx: Context,
    ) -> AsyncIterator[Finding]:
        """Execute the check against ``target``, yielding any findings."""
