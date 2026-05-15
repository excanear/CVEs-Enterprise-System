"""AI Correlation Layer — domain event schemas.

Topic: acl.correlation.events
All payloads extend _ACLBase (frozen Pydantic model).
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

ACL_CORRELATION_TOPIC = "acl.correlation.events"

ACL_EVENT_TYPES: dict[str, str] = {
    "cluster_created": "acl.cluster.created",
    "path_ranked": "acl.path.ranked",
    "exposure_prioritized": "acl.exposure.prioritized",
    "remediation_generated": "acl.remediation.generated",
}


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class _ACLBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class ClusterCreatedPayload(_ACLBase):
    """Emitted when an evidence cluster is formed from related exposures."""

    cluster_id: str
    tenant_id: str
    session_id: str
    size: int
    exposure_types: list[str]
    host: str | None = None
    avg_confidence: float = Field(ge=0.0, le=1.0)
    poc_triggered_count: int = 0
    tier: str  # RiskTier value


class RankedPathEntry(_ACLBase):
    source_endpoint_id: str
    target_asset_id: str
    hops: int
    composite_score: float = Field(ge=0.0, le=1.0)
    rank: int


class PathRankedPayload(_ACLBase):
    """Emitted when attack paths are sorted by composite risk score."""

    tenant_id: str
    session_id: str
    ranked_paths: list[RankedPathEntry]
    total: int


class ExposurePrioritizedPayload(_ACLBase):
    """Emitted when an exposure receives a risk tier assignment."""

    exposure_id: str
    tenant_id: str
    session_id: str
    target_url: str
    exposure_type: str
    tier: str  # RiskTier value
    composite_score: float = Field(ge=0.0, le=1.0)
    rationale: str


class RemediationGeneratedPayload(_ACLBase):
    """Emitted when a remediation plan is produced for a cluster."""

    cluster_id: str
    tenant_id: str
    session_id: str
    exposure_type: str
    steps: list[str]
    llm_enriched: bool = False
    llm_narrative: str | None = None
