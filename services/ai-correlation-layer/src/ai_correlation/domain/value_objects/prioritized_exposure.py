"""PrioritizedExposure — exposure finding with assigned risk tier."""
from __future__ import annotations

from dataclasses import dataclass, field

from cves_event_schemas.acl.acl_events import RiskTier


@dataclass(frozen=True)
class TierFactors:
    """Factors that drove the tier decision — for auditability."""

    confidence: float
    poc_triggered: bool
    propagation_depth: int
    exposure_type: str


@dataclass(frozen=True)
class PrioritizedExposure:
    """Exposure finding with a risk tier and rationale."""

    exposure_id: str        # EVE job_id
    tenant_id: str
    target_url: str
    exposure_type: str
    tier: RiskTier
    composite_score: float  # 0–1, used for intra-tier ordering
    rationale: str
    factors: TierFactors
    path_node_ids: list[str] = field(default_factory=list)
