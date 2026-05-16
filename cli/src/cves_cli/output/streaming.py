"""Async polling helpers and Rich Live progress for non-TUI commands."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

T = TypeVar("T")

_TERMINAL_STATES = frozenset(
    {
        "COMPLETED",
        "FAILED",
        "ERROR",
        "CANCELLED",
        "CANCELED",
        "ABORTED",
        "PARTIAL",
        "SUCCESS",
    }
)


def is_terminal(status: str) -> bool:
    return status.upper().replace("-", "_").replace(" ", "_") in _TERMINAL_STATES


async def poll_until_terminal(
    fetch: Callable[[], Awaitable[dict]],
    *,
    interval: float = 2.0,
    timeout: float = 3600.0,
    on_update: Callable[[dict], None] | None = None,
) -> dict:
    """Poll `fetch()` until the returned dict's status is terminal.

    Returns the final status dict.
    """
    elapsed = 0.0
    while elapsed < timeout:
        data = await fetch()
        status = data.get("status", data.get("scan_status", "UNKNOWN"))
        if on_update:
            on_update(data)
        if is_terminal(status):
            return data
        await asyncio.sleep(interval)
        elapsed += interval
    raise TimeoutError(f"Polling timed out after {timeout}s")


class RichLivePoller:
    """Renders a Rich Live panel while polling. Falls back gracefully in CI mode."""

    def __init__(self, title: str = "Polling…") -> None:
        self._title = title
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            transient=True,
        )
        self._live = Live(self._progress, refresh_per_second=4, console=Console(stderr=True))
        self._task_id: Any = None

    def __enter__(self) -> "RichLivePoller":
        self._live.__enter__()
        self._task_id = self._progress.add_task(self._title, total=None)
        return self

    def __exit__(self, *args: Any) -> None:
        self._live.__exit__(*args)

    def update(self, description: str, *, completed: float | None = None, total: float | None = None) -> None:
        kwargs: dict[str, Any] = {"description": description}
        if completed is not None:
            kwargs["completed"] = completed
        if total is not None:
            kwargs["total"] = total
        self._progress.update(self._task_id, **kwargs)
