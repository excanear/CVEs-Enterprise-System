"""Correlation Service — facade wiring all algorithms and infrastructure.

Responsibilities:
  1. Maintain an in-memory evidence buffer keyed by tenant_id (from Kafka).
  2. On correlate() command: run DBSCAN + ranker + prioritizer + remediation.
  3. Publish results to Kafka and persist to PG.
  4. Expose query methods backed by Redis cache.
"""
from __future__ import annotations

import asyncio
import hashlib
from collections import defaultdict
from typing import Any

import structlog

from cves_event_schemas.acl.acl_events import RiskTier
from cves_event_schemas.envelope import DomainEventEnvelope

from ai_correlation.application.algorithms.attack_path_ranker import AttackPathRanker
from ai_correlation.application.algorithms.evidence_clusterer import EvidenceClusterer
from ai_correlation.application.algorithms.exposure_prioritizer import ExposurePrioritizer
from ai_correlation.application.algorithms.remediation_generator import RemediationGenerator
from ai_correlation.application.commands import (
    GetPrioritizedExposuresCommand,
    GetRankedPathsCommand,
    GetRemediationCommand,
    GetRiskSummaryCommand,
    GetSessionCommand,
    ListClustersCommand,
    TriggerCorrelationCommand,
)
from ai_correlation.domain.entities.correlation_session import (
    CorrelationSession,
    SessionStatus,
)
from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster, EvidenceItem
from ai_correlation.domain.ports import (
    CorrelationCache,
    CorrelationEventPublisher,
    CorrelationRepository,
)
from ai_correlation.domain.value_objects.prioritized_exposure import PrioritizedExposure
from ai_correlation.domain.value_objects.ranked_attack_path import RankedAttackPath
from ai_correlation.domain.value_objects.remediation_plan import RemediationPlan
from ai_correlation.domain.value_objects.risk_summary import RiskSummary, TopFinding
from cves_db.types import uuid7

log = structlog.get_logger(__name__)

_EVE_CONFIRMED = "eve.exposure.confirmed"
_EVE_VALIDATION_COMPLETED = "eve.exposure.validation_completed"
_AGE_ATTACK_PATH = "age.graph.attack_path_discovered"
_AGE_PROPAGATED = "age.graph.exposure_propagated"


class CorrelationService:
    """Application facade: wires evidence buffers, algorithms, infra."""

    def __init__(
        self,
        *,
        repository: CorrelationRepository,
        cache: CorrelationCache,
        publisher: CorrelationEventPublisher,
        clusterer: EvidenceClusterer,
        ranker: AttackPathRanker,
        prioritizer: ExposurePrioritizer,
        remediation: RemediationGenerator,
    ) -> None:
        self._repo = repository
        self._cache = cache
        self._pub = publisher
        self._clusterer = clusterer
        self._ranker = ranker
        self._prioritizer = prioritizer
        self._remediation = remediation

        # In-memory buffers — keyed by tenant_id
        # These accumulate Kafka signals between correlate() calls
        self._evidence_buffer: dict[str, list[EvidenceItem]] = defaultdict(list)
        self._path_buffer: dict[str, list[dict]] = defaultdict(list)
        self._propagation_buffer: dict[str, dict[str, int]] = defaultdict(dict)
        self._confidence_updates: dict[str, dict[str, float]] = defaultdict(dict)
        self._lock = asyncio.Lock()

    # ── Kafka ingestion ────────────────────────────────────────────────────

    async def handle_kafka_signal(self, envelope: DomainEventEnvelope) -> None:
        event_type = envelope.event_type
        payload: dict[str, Any] = envelope.payload  # type: ignore[assignment]

        try:
            if event_type == _EVE_CONFIRMED:
                await self._ingest_exposure_confirmed(payload)
            elif event_type == _EVE_VALIDATION_COMPLETED:
                await self._ingest_validation_completed(payload)
            elif event_type == _AGE_ATTACK_PATH:
                await self._ingest_attack_path(payload)
            elif event_type == _AGE_PROPAGATED:
                await self._ingest_propagation(payload)
            else:
                log.debug("acl.signal.ignored", event_type=event_type)
        except Exception as exc:
            log.warning("acl.signal.error", event_type=event_type, error=str(exc))

    async def _ingest_exposure_confirmed(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id", "")
        item = EvidenceItem(
            evidence_id=payload.get("job_id", str(uuid7())),
            tenant_id=tenant_id,
            exposure_type=payload.get("exposure_type", "EXPOSED_API"),
            target_url=payload.get("target_url", ""),
            confidence=float(payload.get("final_confidence", 0.0)),
            poc_triggered=bool(payload.get("poc_triggered", False)),
            propagation_depth=0,
            hop_count=0,
            host=_extract_host(payload.get("target_url", "")),
            evidence_summary=payload.get("evidence_summary"),
        )
        async with self._lock:
            # Deduplicate by evidence_id
            existing_ids = {e.evidence_id for e in self._evidence_buffer[tenant_id]}
            if item.evidence_id not in existing_ids:
                self._evidence_buffer[tenant_id].append(item)
                log.debug("acl.buffer.evidence_added", tenant_id=tenant_id, evidence_id=item.evidence_id)

    async def _ingest_validation_completed(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id", "")
        job_id = payload.get("job_id", "")
        confidence = float(payload.get("final_confidence", 0.0))
        async with self._lock:
            self._confidence_updates[tenant_id][job_id] = confidence

    async def _ingest_attack_path(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id", "")
        async with self._lock:
            self._path_buffer[tenant_id].append(dict(payload))

    async def _ingest_propagation(self, payload: dict) -> None:
        tenant_id = payload.get("tenant_id", "")
        endpoint_id = payload.get("origin_endpoint_id", "")
        depth = int(payload.get("propagation_depth", 0))
        async with self._lock:
            existing = self._propagation_buffer[tenant_id].get(endpoint_id, 0)
            self._propagation_buffer[tenant_id][endpoint_id] = max(existing, depth)

    # ── Correlation command ────────────────────────────────────────────────

    async def correlate(self, cmd: TriggerCorrelationCommand) -> CorrelationSession:
        """Run full correlation pipeline for a tenant."""
        session = CorrelationSession(
            session_id=cmd.session_id,
            tenant_id=cmd.tenant_id,
        )
        await self._repo.save_session(session)
        session.start()
        await self._repo.update_session(session)

        try:
            async with self._lock:
                # Snapshot buffers for this run
                items = list(self._evidence_buffer.get(cmd.tenant_id, []))
                paths = list(self._path_buffer.get(cmd.tenant_id, []))
                prop_map = dict(self._propagation_buffer.get(cmd.tenant_id, {}))
                conf_updates = dict(self._confidence_updates.get(cmd.tenant_id, {}))

            # Apply confidence updates to items
            updated_items = _apply_confidence_updates(items, conf_updates)

            session.evidence_count = len(updated_items)
            session.path_count = len(paths)

            # 1. Cluster evidence
            clusters = await self._clusterer.cluster(
                updated_items, cmd.tenant_id, cmd.session_id
            )

            # 2. Rank attack paths
            max_depth = max(prop_map.values(), default=1)
            ranked_paths = self._ranker.rank(
                paths,
                tenant_id=cmd.tenant_id,
                propagation_by_endpoint=prop_map,
                max_propagation=max_depth,
            )

            # 3. Prioritize exposures (flat list from all clusters)
            all_items = [item for c in clusters for item in c.items]
            # Enrich items with propagation depth from AGE signals
            prop_by_evidence: dict[str, int] = {}
            prioritized = self._prioritizer.prioritize(
                all_items, propagation_by_evidence=prop_by_evidence
            )

            # 4. Generate remediation for each cluster
            remediation_plans: list[RemediationPlan] = []
            for cluster in clusters:
                plan = await self._remediation.generate(cluster)
                remediation_plans.append(plan)

            # Persist clusters to PG
            for cluster in clusters:
                await self._repo.save_cluster(cluster)

            # Cache results
            await self._cache.set_clusters(cmd.tenant_id, clusters)
            await self._cache.set_ranked_paths(cmd.tenant_id, ranked_paths)
            await self._cache.set_prioritized(cmd.tenant_id, prioritized)
            for plan in remediation_plans:
                await self._cache.set_remediation(plan.cluster_id, plan)

            # Publish Kafka events
            for cluster in clusters:
                await self._pub.publish_cluster_created(cluster)
            if ranked_paths:
                await self._pub.publish_paths_ranked(
                    cmd.tenant_id, cmd.session_id, ranked_paths
                )
            for exposure in prioritized:
                await self._pub.publish_exposure_prioritized(exposure, cmd.session_id)
            for plan in remediation_plans:
                await self._pub.publish_remediation_generated(
                    plan, cmd.tenant_id, cmd.session_id
                )

            session.complete(
                cluster_count=len(clusters),
                prioritized_count=len(prioritized),
            )

        except Exception as exc:
            log.error("acl.correlate.failed", session_id=cmd.session_id, error=str(exc))
            session.fail(str(exc))

        await self._repo.update_session(session)
        return session

    # ── Query methods ──────────────────────────────────────────────────────

    async def get_session(self, cmd: GetSessionCommand) -> CorrelationSession | None:
        return await self._repo.get_session(cmd.session_id)

    async def list_clusters(self, cmd: ListClustersCommand) -> list[EvidenceCluster]:
        # Try cache first (includes item details)
        if cmd.session_id is None:
            cached = await self._cache.get_clusters(cmd.tenant_id)
            if cached is not None:
                return cached
        return await self._repo.list_clusters(cmd.tenant_id, session_id=cmd.session_id)

    async def get_ranked_paths(self, cmd: GetRankedPathsCommand) -> list[RankedAttackPath]:
        cached = await self._cache.get_ranked_paths(cmd.tenant_id)
        if cached is not None:
            return cached[: cmd.limit]
        return []

    async def get_prioritized(
        self, cmd: GetPrioritizedExposuresCommand
    ) -> list[PrioritizedExposure]:
        cached = await self._cache.get_prioritized(cmd.tenant_id)
        if cached is None:
            return []
        result = cached
        if cmd.tier:
            result = [e for e in result if e.tier.value == cmd.tier]
        return result[: cmd.limit]

    async def get_remediation(self, cmd: GetRemediationCommand) -> RemediationPlan | None:
        cached = await self._cache.get_remediation(cmd.cluster_id)
        if cached:
            return cached
        # Regenerate from buffer if cluster exists
        clusters = await self._repo.list_clusters(cmd.tenant_id)
        for c in clusters:
            if c.cluster_id == cmd.cluster_id:
                plan = await self._remediation.generate(c)
                await self._cache.set_remediation(cmd.cluster_id, plan)
                return plan
        return None

    async def get_risk_summary(self, cmd: GetRiskSummaryCommand) -> RiskSummary:
        prioritized = await self._cache.get_prioritized(cmd.tenant_id)
        clusters = await self._repo.list_clusters(cmd.tenant_id, session_id=cmd.session_id)
        ranked = await self._cache.get_ranked_paths(cmd.tenant_id)

        prioritized = prioritized or []
        ranked = ranked or []

        counts: dict[str, int] = {t.value: 0 for t in RiskTier}
        for e in prioritized:
            counts[e.tier.value] = counts.get(e.tier.value, 0) + 1

        top = sorted(prioritized, key=lambda e: e.composite_score, reverse=True)[:5]
        top_findings = [
            TopFinding(
                exposure_id=e.exposure_id,
                target_url=e.target_url,
                exposure_type=e.exposure_type,
                tier=e.tier,
                composite_score=e.composite_score,
            )
            for e in top
        ]

        return RiskSummary(
            session_id=cmd.session_id or "",
            tenant_id=cmd.tenant_id,
            total_exposures=len(prioritized),
            counts_by_tier=counts,
            top_findings=top_findings,
            total_clusters=len(clusters),
            total_attack_paths=len(ranked),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_host(url: str) -> str | None:
    if not url:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.hostname or None
    except Exception:
        return None


def _apply_confidence_updates(
    items: list[EvidenceItem],
    updates: dict[str, float],
) -> list[EvidenceItem]:
    if not updates:
        return items
    result = []
    for item in items:
        if item.evidence_id in updates:
            new_conf = updates[item.evidence_id]
            updated = EvidenceItem(
                evidence_id=item.evidence_id,
                tenant_id=item.tenant_id,
                exposure_type=item.exposure_type,
                target_url=item.target_url,
                confidence=new_conf,
                poc_triggered=item.poc_triggered,
                propagation_depth=item.propagation_depth,
                hop_count=item.hop_count,
                host=item.host,
                evidence_summary=item.evidence_summary,
            )
            result.append(updated)
        else:
            result.append(item)
    return result
