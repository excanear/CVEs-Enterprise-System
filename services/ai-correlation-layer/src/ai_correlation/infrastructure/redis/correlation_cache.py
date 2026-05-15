"""Redis correlation cache — TTL-based caching for DBSCAN + ranking results.

DBSCAN is CPU-bound and runs over all evidence per tenant.
Results are cached for 1 hour to avoid recomputation on every HTTP request.
"""
from __future__ import annotations

import json
from typing import Any

import structlog

from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster, EvidenceItem
from ai_correlation.domain.value_objects.prioritized_exposure import (
    PrioritizedExposure,
    TierFactors,
)
from ai_correlation.domain.value_objects.ranked_attack_path import (
    RankedAttackPath,
    ScoreComponents,
)
from ai_correlation.domain.value_objects.remediation_plan import RemediationPlan
from cves_event_schemas.acl.acl_events import RiskTier

log = structlog.get_logger(__name__)

_TTL_SECONDS = 3600  # 1 hour


class RedisCorrelationCache:
    """Redis adapter implementing the CorrelationCache port."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    # ── Clusters ──────────────────────────────────────────────────────────

    async def get_clusters(self, tenant_id: str) -> list[EvidenceCluster] | None:
        key = f"acl:clusters:{tenant_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return [_deserialize_cluster(c) for c in data]
        except Exception as exc:
            log.warning("acl.cache.clusters.deserialize_error", error=str(exc))
            return None

    async def set_clusters(self, tenant_id: str, clusters: list[EvidenceCluster]) -> None:
        key = f"acl:clusters:{tenant_id}"
        data = [_serialize_cluster(c) for c in clusters]
        await self._redis.setex(key, _TTL_SECONDS, json.dumps(data))

    # ── Ranked paths ──────────────────────────────────────────────────────

    async def get_ranked_paths(self, tenant_id: str) -> list[RankedAttackPath] | None:
        key = f"acl:paths:{tenant_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return [_deserialize_path(p) for p in data]
        except Exception as exc:
            log.warning("acl.cache.paths.deserialize_error", error=str(exc))
            return None

    async def set_ranked_paths(self, tenant_id: str, paths: list[RankedAttackPath]) -> None:
        key = f"acl:paths:{tenant_id}"
        data = [_serialize_path(p) for p in paths]
        await self._redis.setex(key, _TTL_SECONDS, json.dumps(data))

    # ── Prioritized exposures ──────────────────────────────────────────────

    async def get_prioritized(self, tenant_id: str) -> list[PrioritizedExposure] | None:
        key = f"acl:prioritized:{tenant_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return [_deserialize_exposure(e) for e in data]
        except Exception as exc:
            log.warning("acl.cache.prioritized.deserialize_error", error=str(exc))
            return None

    async def set_prioritized(self, tenant_id: str, items: list[PrioritizedExposure]) -> None:
        key = f"acl:prioritized:{tenant_id}"
        data = [_serialize_exposure(e) for e in items]
        await self._redis.setex(key, _TTL_SECONDS, json.dumps(data))

    # ── Remediation ──────────────────────────────────────────────────────

    async def get_remediation(self, cluster_id: str) -> RemediationPlan | None:
        key = f"acl:remediation:{cluster_id}"
        raw = await self._redis.get(key)
        if raw is None:
            return None
        try:
            return _deserialize_plan(json.loads(raw))
        except Exception as exc:
            log.warning("acl.cache.remediation.deserialize_error", error=str(exc))
            return None

    async def set_remediation(self, cluster_id: str, plan: RemediationPlan) -> None:
        key = f"acl:remediation:{cluster_id}"
        await self._redis.setex(key, _TTL_SECONDS, json.dumps(_serialize_plan(plan)))


# ── Serialization helpers ──────────────────────────────────────────────────────

def _serialize_cluster(c: EvidenceCluster) -> dict:
    return {
        "cluster_id": c.cluster_id,
        "tenant_id": c.tenant_id,
        "session_id": c.session_id,
        "tier": c.tier.value,
        "host": c.host,
        "created_at": c.created_at.isoformat(),
        "items": [
            {
                "evidence_id": i.evidence_id,
                "tenant_id": i.tenant_id,
                "exposure_type": i.exposure_type,
                "target_url": i.target_url,
                "confidence": i.confidence,
                "poc_triggered": i.poc_triggered,
                "propagation_depth": i.propagation_depth,
                "hop_count": i.hop_count,
                "host": i.host,
                "evidence_summary": i.evidence_summary,
            }
            for i in c.items
        ],
    }


def _deserialize_cluster(d: dict) -> EvidenceCluster:
    from datetime import datetime, timezone

    items = [
        EvidenceItem(
            evidence_id=i["evidence_id"],
            tenant_id=i["tenant_id"],
            exposure_type=i["exposure_type"],
            target_url=i["target_url"],
            confidence=i["confidence"],
            poc_triggered=i["poc_triggered"],
            propagation_depth=i["propagation_depth"],
            hop_count=i["hop_count"],
            host=i.get("host"),
            evidence_summary=i.get("evidence_summary"),
        )
        for i in d["items"]
    ]
    cluster = EvidenceCluster(
        cluster_id=d["cluster_id"],
        tenant_id=d["tenant_id"],
        session_id=d["session_id"],
        items=items,
        tier=RiskTier(d["tier"]),
        host=d.get("host"),
        created_at=datetime.fromisoformat(d["created_at"]),
    )
    return cluster


def _serialize_path(p: RankedAttackPath) -> dict:
    return {
        "source_endpoint_id": p.source_endpoint_id,
        "target_asset_id": p.target_asset_id,
        "tenant_id": p.tenant_id,
        "hops": p.hops,
        "risk_score": p.risk_score,
        "composite_score": p.composite_score,
        "path_node_ids": p.path_node_ids,
        "rank": p.rank,
        "components": {
            "confidence_score": p.components.confidence_score,
            "hops_score": p.components.hops_score,
            "poc_score": p.components.poc_score,
            "propagation_score": p.components.propagation_score,
            "dep_cvss_score": p.components.dep_cvss_score,
        },
    }


def _deserialize_path(d: dict) -> RankedAttackPath:
    comp = d["components"]
    return RankedAttackPath(
        source_endpoint_id=d["source_endpoint_id"],
        target_asset_id=d["target_asset_id"],
        tenant_id=d["tenant_id"],
        hops=d["hops"],
        risk_score=d["risk_score"],
        composite_score=d["composite_score"],
        path_node_ids=d["path_node_ids"],
        rank=d["rank"],
        components=ScoreComponents(
            confidence_score=comp["confidence_score"],
            hops_score=comp["hops_score"],
            poc_score=comp["poc_score"],
            propagation_score=comp["propagation_score"],
            dep_cvss_score=comp["dep_cvss_score"],
        ),
    )


def _serialize_exposure(e: PrioritizedExposure) -> dict:
    return {
        "exposure_id": e.exposure_id,
        "tenant_id": e.tenant_id,
        "target_url": e.target_url,
        "exposure_type": e.exposure_type,
        "tier": e.tier.value,
        "composite_score": e.composite_score,
        "rationale": e.rationale,
        "path_node_ids": e.path_node_ids,
        "factors": {
            "confidence": e.factors.confidence,
            "poc_triggered": e.factors.poc_triggered,
            "propagation_depth": e.factors.propagation_depth,
            "exposure_type": e.factors.exposure_type,
        },
    }


def _deserialize_exposure(d: dict) -> PrioritizedExposure:
    f = d["factors"]
    return PrioritizedExposure(
        exposure_id=d["exposure_id"],
        tenant_id=d["tenant_id"],
        target_url=d["target_url"],
        exposure_type=d["exposure_type"],
        tier=RiskTier(d["tier"]),
        composite_score=d["composite_score"],
        rationale=d["rationale"],
        path_node_ids=d.get("path_node_ids", []),
        factors=TierFactors(
            confidence=f["confidence"],
            poc_triggered=f["poc_triggered"],
            propagation_depth=f["propagation_depth"],
            exposure_type=f["exposure_type"],
        ),
    )


def _serialize_plan(p: RemediationPlan) -> dict:
    return {
        "cluster_id": p.cluster_id,
        "exposure_type": p.exposure_type,
        "steps": p.steps,
        "llm_enriched": p.llm_enriched,
        "llm_narrative": p.llm_narrative,
        "template_id": p.template_id,
    }


def _deserialize_plan(d: dict) -> RemediationPlan:
    return RemediationPlan(
        cluster_id=d["cluster_id"],
        exposure_type=d["exposure_type"],
        steps=d["steps"],
        llm_enriched=d.get("llm_enriched", False),
        llm_narrative=d.get("llm_narrative"),
        template_id=d.get("template_id", ""),
    )
