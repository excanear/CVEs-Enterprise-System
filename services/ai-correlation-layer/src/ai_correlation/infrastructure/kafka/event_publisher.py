"""Kafka event publisher for AI Correlation Layer.

Publishes to topic: acl.correlation.events
Event types: cluster_created, path_ranked, exposure_prioritized, remediation_generated
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.acl.acl_events import (
    ACL_CORRELATION_TOPIC,
    ACL_EVENT_TYPES,
    ClusterCreatedPayload,
    ExposurePrioritizedPayload,
    PathRankedPayload,
    RankedPathEntry,
    RemediationGeneratedPayload,
)
from cves_kafka_client.producer import BaseKafkaProducer

from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster
from ai_correlation.domain.value_objects.prioritized_exposure import PrioritizedExposure
from ai_correlation.domain.value_objects.ranked_attack_path import RankedAttackPath
from ai_correlation.domain.value_objects.remediation_plan import RemediationPlan

log = structlog.get_logger(__name__)

_SVC_NAME = "ai-correlation-layer"
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def _safe_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return _NIL_UUID


class KafkaACLEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_cluster_created(self, cluster: EvidenceCluster) -> None:
        payload = ClusterCreatedPayload(
            cluster_id=cluster.cluster_id,
            tenant_id=cluster.tenant_id,
            session_id=cluster.session_id,
            size=cluster.size,
            exposure_types=cluster.exposure_types,
            host=cluster.host,
            avg_confidence=cluster.avg_confidence,
            poc_triggered_count=cluster.poc_triggered_count,
            tier=cluster.tier.value,
        )
        await self._publish(
            event_type=ACL_EVENT_TYPES["cluster_created"],
            aggregate_id=cluster.cluster_id,
            aggregate_type="EvidenceCluster",
            tenant_id=cluster.tenant_id,
            payload=payload.model_dump(),
        )

    async def publish_paths_ranked(
        self,
        tenant_id: str,
        session_id: str,
        paths: list[RankedAttackPath],
    ) -> None:
        entries = [
            RankedPathEntry(
                source_endpoint_id=p.source_endpoint_id,
                target_asset_id=p.target_asset_id,
                hops=p.hops,
                composite_score=p.composite_score,
                rank=p.rank,
            )
            for p in paths
        ]
        payload = PathRankedPayload(
            tenant_id=tenant_id,
            session_id=session_id,
            ranked_paths=entries,
            total=len(entries),
        )
        await self._publish(
            event_type=ACL_EVENT_TYPES["path_ranked"],
            aggregate_id=session_id,
            aggregate_type="CorrelationSession",
            tenant_id=tenant_id,
            payload=payload.model_dump(),
        )

    async def publish_exposure_prioritized(
        self,
        exposure: PrioritizedExposure,
        session_id: str,
    ) -> None:
        payload = ExposurePrioritizedPayload(
            exposure_id=exposure.exposure_id,
            tenant_id=exposure.tenant_id,
            session_id=session_id,
            target_url=exposure.target_url,
            exposure_type=exposure.exposure_type,
            tier=exposure.tier.value,
            composite_score=exposure.composite_score,
            rationale=exposure.rationale,
        )
        await self._publish(
            event_type=ACL_EVENT_TYPES["exposure_prioritized"],
            aggregate_id=exposure.exposure_id,
            aggregate_type="PrioritizedExposure",
            tenant_id=exposure.tenant_id,
            payload=payload.model_dump(),
        )

    async def publish_remediation_generated(
        self,
        plan: RemediationPlan,
        tenant_id: str,
        session_id: str,
    ) -> None:
        payload = RemediationGeneratedPayload(
            cluster_id=plan.cluster_id,
            tenant_id=tenant_id,
            session_id=session_id,
            exposure_type=plan.exposure_type,
            steps=plan.steps,
            llm_enriched=plan.llm_enriched,
            llm_narrative=plan.llm_narrative,
        )
        await self._publish(
            event_type=ACL_EVENT_TYPES["remediation_generated"],
            aggregate_id=plan.cluster_id,
            aggregate_type="RemediationPlan",
            tenant_id=tenant_id,
            payload=payload.model_dump(),
        )

    async def _publish(
        self,
        *,
        event_type: str,
        aggregate_id: str,
        aggregate_type: str,
        tenant_id: str,
        payload: dict[str, Any],
    ) -> None:
        envelope = DomainEventEnvelope(
            event_id=uuid7(),
            event_type=event_type,
            schema_version="1.0.0",
            aggregate_id=_safe_uuid(aggregate_id),
            aggregate_type=aggregate_type,
            tenant_id=_safe_uuid(tenant_id),
            correlation_id=uuid7(),
            producer_svc=_SVC_NAME,
            payload=payload,
        )
        try:
            await self._producer.produce_envelope(ACL_CORRELATION_TOPIC, envelope)
        except Exception as exc:
            log.warning("acl.publisher.produce_failed", event_type=event_type, error=str(exc))
