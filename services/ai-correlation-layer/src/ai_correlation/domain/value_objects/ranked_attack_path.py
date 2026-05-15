"""RankedAttackPath — attack path with composite risk score."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreComponents:
    """Individual contributions to the composite score — for auditability."""

    confidence_score: float   # EVE final_confidence × 0.35
    hops_score: float         # (1/hops) × 0.25
    poc_score: float          # poc_triggered × 0.20
    propagation_score: float  # propagation_depth_norm × 0.15
    dep_cvss_score: float     # dep_cvss_norm × 0.05


@dataclass(frozen=True)
class RankedAttackPath:
    """Attack path enriched with composite risk ranking."""

    source_endpoint_id: str
    target_asset_id: str
    tenant_id: str
    hops: int
    risk_score: float           # original AGE risk score
    composite_score: float      # ACL composite (0–1)
    components: ScoreComponents
    path_node_ids: list[str]
    rank: int = 0               # 1-based after sorting
