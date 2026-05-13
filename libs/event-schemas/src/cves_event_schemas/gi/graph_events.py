"""GI (Graph Intelligence) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _GIBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class PathNodePayload(_GIBase):
    """A node in an attack path."""

    node_id: str
    node_type: Literal["ASSET", "EXPOSURE", "NETWORK_ZONE", "INTERNET"]
    label: str
    criticality: str | None = None
    risk_score: float | None = None


class PathEdgePayload(_GIBase):
    """An edge (relationship) in an attack path."""

    from_node_id: str
    to_node_id: str
    relationship: Literal[
        "EXPOSED_TO", "REACHABLE_VIA", "DEPENDS_ON",
        "LATERAL_MOVEMENT", "PRIVILEGE_ESCALATION", "IN_ZONE"
    ]
    weight: float = Field(ge=0.0, le=1.0)


class AttackPathComputedPayload(_GIBase):
    """Payload for event_type='gi.attack_path.computed'."""

    path_id: uuid.UUID
    source_node: PathNodePayload
    target_node: PathNodePayload
    intermediate_nodes: list[PathNodePayload] = Field(default_factory=list)
    edges: list[PathEdgePayload] = Field(default_factory=list)
    hop_count: int
    total_risk_score: float = Field(ge=0.0, le=10.0)
    exploitability_score: float = Field(ge=0.0, le=10.0)
    blast_radius_count: int
    critical_node_ids: list[str] = Field(default_factory=list)
    cypher_query_hash: str


class AttackPathInvalidatedPayload(_GIBase):
    """Payload for event_type='gi.attack_path.invalidated'."""

    path_id: uuid.UUID
    invalidation_reasons: list[str]
    former_risk_score: float


class BlastRadiusAnalyzedPayload(_GIBase):
    """Payload for event_type='gi.blast_radius.analyzed'."""

    path_id: uuid.UUID
    asset_id: uuid.UUID
    blast_radius_count: int
    affected_asset_ids: list[uuid.UUID]
    max_propagated_risk: float = Field(ge=0.0, le=10.0)
    analysis_depth: int


class CriticalNodeIdentifiedPayload(_GIBase):
    """Payload for event_type='gi.critical_node.identified'.

    Emitted when a node is identified as a bottleneck whose compromise
    would affect N or more critical downstream assets.
    """

    path_id: uuid.UUID
    critical_node_ids: list[str]
    blast_radius_count: int
    downstream_critical_count: int
    remediation_priority: Literal["CRITICAL", "HIGH", "MEDIUM"]


GI_GRAPH_TOPIC = "gi.graph.events"

GI_EVENT_TYPES = {
    "attack_path_computed": "gi.attack_path.computed",
    "attack_path_invalidated": "gi.attack_path.invalidated",
    "blast_radius_analyzed": "gi.blast_radius.analyzed",
    "critical_node_identified": "gi.critical_node.identified",
    "attack_path_stale": "gi.attack_path.stale",
}
