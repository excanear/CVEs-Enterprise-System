"""Asset Graph Engine — domain event schemas.

Topic: age.graph.events
All payloads extend _AGEBase (frozen Pydantic model).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

AGE_GRAPH_TOPIC = "age.graph.events"

AGE_EVENT_TYPES: dict[str, str] = {
    "node_upserted": "age.graph.node_upserted",
    "edge_upserted": "age.graph.edge_upserted",
    "attack_path_discovered": "age.graph.attack_path_discovered",
    "exposure_propagated": "age.graph.exposure_propagated",
}


class _AGEBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class NodeUpsertedPayload(_AGEBase):
    """Emitted whenever a graph node is created or updated."""

    node_id: str
    tenant_id: str
    label: str  # Asset | Endpoint | Service | Dependency | Route
    url: str | None = None
    host: str | None = None
    properties: dict = Field(default_factory=dict)


class EdgeUpsertedPayload(_AGEBase):
    """Emitted whenever a graph relationship is created or updated."""

    from_id: str
    to_id: str
    tenant_id: str
    edge_type: str  # EXPOSES | CALLS | TRUSTS | DEPENDS_ON | HOSTED_ON | ...
    properties: dict = Field(default_factory=dict)


class AttackPathDiscoveredPayload(_AGEBase):
    """Emitted when a new attack path is identified in the graph."""

    tenant_id: str
    source_endpoint_id: str
    target_asset_id: str
    hops: int
    path_node_ids: list[str]
    risk_score: float = Field(ge=0.0, le=1.0)


class ExposurePropagatedPayload(_AGEBase):
    """Emitted when exposure is propagated transitively through CALLS/TRUSTS edges."""

    tenant_id: str
    origin_endpoint_id: str
    affected_asset_ids: list[str]
    propagation_depth: int
    max_hops_reached: bool = False
