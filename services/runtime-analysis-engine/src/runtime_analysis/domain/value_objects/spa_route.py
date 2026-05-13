from __future__ import annotations

from pydantic import BaseModel


class SPARoute(BaseModel, frozen=True):
    """Value object for a SPA route discovered via history.pushState instrumentation."""

    path: str
    triggered_by: str  # "pushState" | "replaceState" | "popstate" | "initial"
    lazy_chunks: tuple[str, ...] = ()
    api_calls_count: int = 0
