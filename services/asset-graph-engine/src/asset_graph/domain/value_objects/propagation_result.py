"""Value object: ExposurePropagation.

Represents the set of Assets transitively reachable from a confirmed exposure
through CALLS and TRUSTS relationships (APOC subgraphNodes traversal).
Immutable (frozen Pydantic model).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PropagationHop(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    url: str | None = None
    host: str | None = None
    hop_distance: int = Field(ge=1)
    reached_via: str  # edge type that led here: CALLS | TRUSTS


class ExposurePropagation(BaseModel):
    """BFS result from a TRUE_POSITIVE Endpoint via CALLS/TRUSTS edges."""

    model_config = ConfigDict(frozen=True)

    origin_endpoint_id: str
    tenant_id: str
    affected_assets: tuple[PropagationHop, ...] = Field(default_factory=tuple)
    propagation_depth: int = Field(ge=0)
    max_hops_reached: bool = False

    @property
    def affected_count(self) -> int:
        return len(self.affected_assets)
