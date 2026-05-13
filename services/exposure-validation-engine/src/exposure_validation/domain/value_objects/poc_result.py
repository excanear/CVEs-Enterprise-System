"""PoCResult — safe proof-of-concept probe result."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


ProbeType = Literal["TIMING", "REFLECTION", "CORS_PROBE", "HEADER_INJECTION", "NONE"]


class PoCResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    probe_type: ProbeType = "NONE"
    triggered: bool = False
    evidence: str | None = None
    safe: bool = True

    @classmethod
    def no_probe(cls) -> "PoCResult":
        return cls(probe_type="NONE", triggered=False, safe=True)
