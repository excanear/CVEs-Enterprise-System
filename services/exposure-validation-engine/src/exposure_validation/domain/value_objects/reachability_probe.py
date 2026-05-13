"""ReachabilityProbeResult — output of the runtime reachability check."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ReachabilityProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    endpoint_url: str
    is_reachable: bool
    http_status: int | None = None
    response_time_ms: float | None = None
    required_playwright: bool = False
    error: str | None = None

    @classmethod
    def unreachable(cls, url: str, error: str) -> "ReachabilityProbeResult":
        return cls(endpoint_url=url, is_reachable=False, error=error)
