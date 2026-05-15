"""Evidence Clusterer — DBSCAN-based grouping of related exposure findings.

Algorithm:
  1. Build numpy feature matrix from EvidenceItem list (via feature_extractor).
  2. Run DBSCAN with eps=0.3, min_samples=2.
  3. Group items by DBSCAN label.
  4. Label=-1 (noise) → each item becomes a singleton cluster.
  5. Assign RiskTier to each cluster via ExposurePrioritizer rules on cluster stats.

No vulnerability invention: only groups items already validated by EVE/AGE.
"""
from __future__ import annotations

import hashlib
import asyncio
from collections import defaultdict

import structlog

from cves_event_schemas.acl.acl_events import RiskTier

from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster, EvidenceItem
from ai_correlation.infrastructure.ai.feature_extractor import build_feature_matrix

log = structlog.get_logger(__name__)

_DBSCAN_EPS = 0.3
_DBSCAN_MIN_SAMPLES = 2


def _cluster_tier(items: list[EvidenceItem]) -> RiskTier:
    """Assign a risk tier to a cluster based on its aggregate statistics."""
    avg_conf = sum(i.confidence for i in items) / max(len(items), 1)
    poc_any = any(i.poc_triggered for i in items)
    max_depth = max((i.propagation_depth for i in items), default=0)

    if avg_conf >= 0.85 and (poc_any or max_depth >= 3):
        return RiskTier.CRITICAL
    if avg_conf >= 0.70 or poc_any:
        return RiskTier.HIGH
    if avg_conf >= 0.50:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def _cluster_host(items: list[EvidenceItem]) -> str | None:
    hosts = {i.host for i in items if i.host}
    if len(hosts) == 1:
        return hosts.pop()
    return None


def _cluster_id(tenant_id: str, label: int, session_id: str) -> str:
    key = f"{tenant_id}:{session_id}:{label}"
    return hashlib.sha256(key.encode()).hexdigest()[:36]


class EvidenceClusterer:
    """Groups evidence items using DBSCAN clustering."""

    async def cluster(
        self,
        items: list[EvidenceItem],
        tenant_id: str,
        session_id: str,
    ) -> list[EvidenceCluster]:
        if not items:
            return []

        if len(items) == 1:
            # No point running DBSCAN on a single item
            cluster = EvidenceCluster(
                cluster_id=_cluster_id(tenant_id, 0, session_id),
                tenant_id=tenant_id,
                session_id=session_id,
                items=list(items),
                tier=_cluster_tier(items),
                host=_cluster_host(items),
            )
            return [cluster]

        # Run DBSCAN in thread to avoid blocking the event loop (CPU-bound)
        labels = await asyncio.to_thread(self._run_dbscan, items)

        # Group items by cluster label
        groups: dict[int, list[EvidenceItem]] = defaultdict(list)
        for item, label in zip(items, labels):
            groups[label].append(item)

        clusters: list[EvidenceCluster] = []
        singleton_counter = 0

        for label, group_items in groups.items():
            if label == -1:
                # Noise → each becomes a singleton cluster
                for idx, singleton in enumerate(group_items):
                    cid = _cluster_id(tenant_id, -(idx + 1 + singleton_counter), session_id)
                    clusters.append(
                        EvidenceCluster(
                            cluster_id=cid,
                            tenant_id=tenant_id,
                            session_id=session_id,
                            items=[singleton],
                            tier=_cluster_tier([singleton]),
                            host=singleton.host,
                        )
                    )
                singleton_counter += len(group_items)
            else:
                cid = _cluster_id(tenant_id, label, session_id)
                clusters.append(
                    EvidenceCluster(
                        cluster_id=cid,
                        tenant_id=tenant_id,
                        session_id=session_id,
                        items=group_items,
                        tier=_cluster_tier(group_items),
                        host=_cluster_host(group_items),
                    )
                )

        log.info(
            "acl.clusterer.done",
            tenant_id=tenant_id,
            n_items=len(items),
            n_clusters=len(clusters),
        )
        return clusters

    def _run_dbscan(self, items: list[EvidenceItem]) -> list[int]:
        from sklearn.cluster import DBSCAN  # type: ignore[import-untyped]

        matrix = build_feature_matrix(items)
        db = DBSCAN(eps=_DBSCAN_EPS, min_samples=_DBSCAN_MIN_SAMPLES, metric="euclidean")
        db.fit(matrix)
        return db.labels_.tolist()
