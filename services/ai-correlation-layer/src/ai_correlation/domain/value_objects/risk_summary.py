"""RiskSummary — aggregated risk dashboard for a tenant/session."""
from __future__ import annotations

from dataclasses import dataclass, field

from cves_event_schemas.acl.acl_events import RiskTier


@dataclass(frozen=True)
class TopFinding:
    exposure_id: str
    target_url: str
    exposure_type: str
    tier: RiskTier
    composite_score: float


@dataclass(frozen=True)
class RiskSummary:
    """Aggregated risk counts and top critical findings for a session."""

    session_id: str
    tenant_id: str
    total_exposures: int
    counts_by_tier: dict[str, int]       # RiskTier.value → count
    top_findings: list[TopFinding]       # up to 5, sorted by composite_score DESC
    total_clusters: int
    total_attack_paths: int
