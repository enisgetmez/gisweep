"""Shared rich.progress wrapper for the scan runtimes.

Wraps :class:`rich.progress.Progress` with a simple ``advance`` callback that
the runner can invoke after each (check, target) pair completes. The bar is
``transient=True`` so it disappears once the findings table is rendered, and
it shares the ``Console`` with the surrounding runtime so the auto-correct /
discovery summary lines don't fight the progress redraw.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from rich.console import Console

    from gisweep.core.runner import CheckProgress


_MAX_URL_DISPLAY = 56


def _truncate(value: str, limit: int = _MAX_URL_DISPLAY) -> str:
    if len(value) <= limit:
        return value
    return f"…{value[-(limit - 1) :]}"


@contextmanager
def progress_callback(
    console: Console | None,
    *,
    description: str = "Running checks",
) -> Iterator[Callable[[CheckProgress], None]]:
    """Yield a runner-compatible ``on_progress`` callback.

    When ``console`` is ``None`` the callback is a no-op so non-interactive
    consumers (tests, JSON-only CI runs) pay zero overhead. Otherwise the
    callback drives a transient rich.progress.Progress bar.
    """
    if console is None:
        yield _noop
        return

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
    with progress:
        task_id = progress.add_task(description, total=None)

        def _advance(snapshot: CheckProgress) -> None:
            progress.update(
                task_id,
                total=snapshot.total,
                completed=snapshot.completed,
                description=f"{snapshot.check_id} • {_truncate(snapshot.target_url)}",
            )

        yield _advance


def _noop(_: CheckProgress) -> None:
    return
