"""Value object: AttackPath.

Represents a shortest path from a confirmed exposure endpoint to a target asset.
Immutable (frozen Pydantic model).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PathNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    node_id: str
    label: str
    url: str | None = None
    host: str | None = None


class AttackPath(BaseModel):
    """A shortest path from a TRUE_POSITIVE Endpoint to a reachable Asset."""

    model_config = ConfigDict(frozen=True)

    source_endpoint_id: str
    target_asset_id: str
    hops: int = Field(ge=1)
    nodes: tuple[PathNode, ...] = Field(default_factory=tuple)
    risk_score: float = Field(ge=0.0, le=1.0, default=0.5)

    @property
    def node_ids(self) -> list[str]:
        return [n.node_id for n in self.nodes]
