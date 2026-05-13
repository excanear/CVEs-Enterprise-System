from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class WebSocketEndpoint(BaseModel, frozen=True):
    """Value object representing a discovered WebSocket endpoint."""

    url: str
    protocols: tuple[str, ...] = ()
    message_samples: tuple[str, ...] = ()
    first_seen_at: datetime
