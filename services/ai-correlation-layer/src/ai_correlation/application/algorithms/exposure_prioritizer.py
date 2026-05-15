"""Exposure Prioritizer — deterministic multi-factor tier assignment.

Tiers and rules:
  CRITICAL → confidence ≥ 0.85 AND (poc_triggered OR propagation_depth ≥ 3)
  HIGH     → confidence ≥ 0.70 OR poc_triggered
  MEDIUM   → confidence ≥ 0.50
  LOW      → confidence < 0.50

Composite score (for intra-tier ordering):
  score = confidence * 0.50 + poc * 0.30 + depth_norm * 0.20

No ML — explicit, auditable thresholds only.
"""
from __future__ import annotations

import structlog

from cves_event_schemas.acl.acl_events import RiskTier

from ai_correlation.domain.entities.evidence_cluster import EvidenceItem
from ai_correlation.domain.value_objects.prioritized_exposure import (
    PrioritizedExposure,
    TierFactors,
)

log = structlog.get_logger(__name__)

_MAX_PROPAGATION_DEPTH = 10.0
_CRITICAL_CONF = 0.85
_HIGH_CONF = 0.70
_MEDIUM_CONF = 0.50


def _compute_score(confidence: float, poc: bool, prop_depth: int) -> float:
    depth_norm = min(float(prop_depth), _MAX_PROPAGATION_DEPTH) / _MAX_PROPAGATION_DEPTH
    return min(confidence * 0.50 + (1.0 if poc else 0.0) * 0.30 + depth_norm * 0.20, 1.0)


def _determine_tier(confidence: float, poc: bool, prop_depth: int) -> tuple[RiskTier, str]:
    if confidence >= _CRITICAL_CONF and (poc or prop_depth >= 3):
        factors = []
        if confidence >= _CRITICAL_CONF:
            factors.append(f"confidence={confidence:.2f}")
        if poc:
            factors.append("poc_triggered")
        if prop_depth >= 3:
            factors.append(f"propagation_depth={prop_depth}")
        return RiskTier.CRITICAL, f"CRITICAL: {', '.join(factors)}"

    if confidence >= _HIGH_CONF or poc:
        factors = []
        if confidence >= _HIGH_CONF:
            factors.append(f"confidence={confidence:.2f}")
        if poc:
            factors.append("poc_triggered")
        return RiskTier.HIGH, f"HIGH: {', '.join(factors)}"

    if confidence >= _MEDIUM_CONF:
        return RiskTier.MEDIUM, f"MEDIUM: confidence={confidence:.2f}"

    return RiskTier.LOW, f"LOW: confidence={confidence:.2f}"


class ExposurePrioritizer:
    """Assigns risk tiers to exposure items using deterministic thresholds."""

    def prioritize(
        self,
        items: list[EvidenceItem],
        *,
        propagation_by_evidence: dict[str, int] | None = None,
    ) -> list[PrioritizedExposure]:
        """Return PrioritizedExposure list sorted by tier severity then composite score."""
        prop_map = propagation_by_evidence or {}
        result: list[PrioritizedExposure] = []

        for item in items:
            prop_depth = prop_map.get(item.evidence_id, item.propagation_depth)
            tier, rationale = _determine_tier(item.confidence, item.poc_triggered, prop_depth)
            score = _compute_score(item.confidence, item.poc_triggered, prop_depth)

            result.append(
                PrioritizedExposure(
                    exposure_id=item.evidence_id,
                    tenant_id=item.tenant_id,
                    target_url=item.target_url,
                    exposure_type=item.exposure_type,
                    tier=tier,
                    composite_score=score,
                    rationale=rationale,
                    factors=TierFactors(
                        confidence=item.confidence,
                        poc_triggered=item.poc_triggered,
                        propagation_depth=prop_depth,
                        exposure_type=item.exposure_type,
                    ),
                )
            )

        # Sort: CRITICAL > HIGH > MEDIUM > LOW, then composite_score DESC
        tier_order = {
            RiskTier.CRITICAL: 0,
            RiskTier.HIGH: 1,
            RiskTier.MEDIUM: 2,
            RiskTier.LOW: 3,
        }
        result.sort(key=lambda e: (tier_order[e.tier], -e.composite_score))

        log.info(
            "acl.prioritizer.done",
            n_items=len(result),
            critical=sum(1 for e in result if e.tier == RiskTier.CRITICAL),
            high=sum(1 for e in result if e.tier == RiskTier.HIGH),
        )
        return result
