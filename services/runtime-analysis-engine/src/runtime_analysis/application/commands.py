from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeURLCommand(BaseModel, frozen=True):
    """Command triggering a full runtime analysis of the given URL."""

    tenant_id: str
    target_url: str
    correlation_id: str
    max_spa_routes: int = Field(default=20, ge=1, le=100)
    timeout_seconds: int = Field(default=120, ge=10, le=600)
    follow_redirects: bool = True
