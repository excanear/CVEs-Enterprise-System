from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HiddenRoute(BaseModel):
    """A route inferred from static JS analysis."""

    model_config = ConfigDict(frozen=True)

    path: str
    router_type: Literal[
        "REACT_ROUTER", "VUE_ROUTER", "ANGULAR", "NEXT_JS", "NUXT", "INFERRED"
    ]
    component_hint: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    discovered_in_chunk: str
    lazy_chunks: tuple[str, ...] = ()
