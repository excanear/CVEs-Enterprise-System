"""Attack Path Ranker — deterministic composite scoring of attack paths.

Formula (weights sum to 1.0):
  composite = confidence * 0.35
            + (1 / max(hops, 1)) * 0.25
            + poc_triggered * 0.20
            + propagation_depth_norm * 0.15
            + dep_cvss_norm * 0.05

All components are normalized to [0, 1]. Fully reproducible — no randomness.
"""
from __future__ import annotations

import structlog

from ai_correlation.domain.value_objects.ranked_attack_path import (
    RankedAttackPath,
    ScoreComponents,
)

log = structlog.get_logger(__name__)

_MAX_PROPAGATION_DEPTH = 10.0
_W_CONFIDENCE = 0.35
_W_HOPS = 0.25
_W_POC = 0.20
_W_PROPAGATION = 0.15
_W_DEP_CVSS = 0.05


class AttackPathRanker:
    """Ranks attack paths by a deterministic composite risk score."""

    def rank(
        self,
        paths: list[dict],
        *,
        tenant_id: str,
        propagation_by_endpoint: dict[str, int] | None = None,
        max_propagation: int = 1,
    ) -> list[RankedAttackPath]:
        """Score and rank attack path dictionaries from AGE events.

        Args:
            paths: list of dicts with keys matching AttackPathDiscoveredPayload fields
            tenant_id: tenant scoping
            propagation_by_endpoint: maps source_endpoint_id → propagation_depth
            max_propagation: max depth seen across all propagation events (for normalization)
        """
        prop_map = propagation_by_endpoint or {}
        _max_prop = max(float(max_propagation), 1.0)
        ranked: list[RankedAttackPath] = []

        for p in paths:
            hops = max(int(p.get("hops", 1)), 1)
            confidence = float(p.get("confidence", 0.0))
            poc = bool(p.get("poc_triggered", False))
            dep_cvss = float(p.get("dep_cvss", 0.0))
            prop_depth = prop_map.get(p.get("source_endpoint_id", ""), 0)

            confidence_component = confidence * _W_CONFIDENCE
            hops_component = (1.0 / hops) * _W_HOPS
            poc_component = (1.0 if poc else 0.0) * _W_POC
            propagation_component = min(float(prop_depth), _max_prop) / _max_prop * _W_PROPAGATION
            dep_cvss_component = min(dep_cvss / 10.0, 1.0) * _W_DEP_CVSS

            composite = (
                confidence_component
                + hops_component
                + poc_component
                + propagation_component
                + dep_cvss_component
            )
            composite = min(max(composite, 0.0), 1.0)

            ranked.append(
                RankedAttackPath(
                    source_endpoint_id=p.get("source_endpoint_id", ""),
                    target_asset_id=p.get("target_asset_id", ""),
                    tenant_id=tenant_id,
                    hops=hops,
                    risk_score=float(p.get("risk_score", 0.0)),
                    composite_score=composite,
                    path_node_ids=list(p.get("path_node_ids", [])),
                    components=ScoreComponents(
                        confidence_score=confidence_component,
                        hops_score=hops_component,
                        poc_score=poc_component,
                        propagation_score=propagation_component,
                        dep_cvss_score=dep_cvss_component,
                    ),
                )
            )

        # Sort descending by composite score, then assign 1-based ranks
        ranked.sort(key=lambda r: r.composite_score, reverse=True)
        result: list[RankedAttackPath] = []
        for i, r in enumerate(ranked):
            result.append(
                RankedAttackPath(
                    source_endpoint_id=r.source_endpoint_id,
                    target_asset_id=r.target_asset_id,
                    tenant_id=r.tenant_id,
                    hops=r.hops,
                    risk_score=r.risk_score,
                    composite_score=r.composite_score,
                    path_node_ids=r.path_node_ids,
                    components=r.components,
                    rank=i + 1,
                )
            )

        log.info("acl.ranker.done", tenant_id=tenant_id, n_paths=len(result))
        return result
