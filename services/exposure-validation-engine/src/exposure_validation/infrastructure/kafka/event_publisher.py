"""Kafka event publisher for the Exposure Validation Engine.

Publishes to topic: eve.exposure.events
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.eve.eve_events import (
    EVE_EXPOSURE_TOPIC,
    EVE_EVENT_TYPES,
    ExposureConfirmedPayload,
    ExposureCandidateReceivedPayload,
    ValidationCompletedPayload,
    ValidationVerdict,
)
from cves_kafka_client.producer import BaseKafkaProducer

from exposure_validation.domain.entities.validation_job import ValidationJob
from exposure_validation.domain.entities.validation_result import ValidationResult

log = structlog.get_logger(__name__)

_SVC_NAME = "exposure-validation-engine"
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


class KafkaEVEEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_result(
        self,
        job: ValidationJob,
        result: ValidationResult,
    ) -> None:
        tenant_id = job.tenant_id
        correlation_id = job.correlation_id or str(uuid7())

        # 1. ValidationCompleted — always emitted
        completed_payload = ValidationCompletedPayload(
            job_id=job.job_id,
            tenant_id=tenant_id,
            target_url=job.target_url,
            exposure_type=job.exposure_type.value,
            verdict=result.verdict.value,
            final_confidence=result.final_confidence,
            stages_passed=list(result.stages_passed),
            evidence_count=result.evidence_count,
            duration_seconds=job.duration_seconds,
        )
        await self._publish(
            event_type=EVE_EVENT_TYPES["validation_completed"],
            aggregate_id=result.result_id,
            aggregate_type="ValidationResult",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            payload=completed_payload.model_dump(),
        )

        # 2. ExposureConfirmed — only for TRUE_POSITIVE
        if result.verdict == ValidationVerdict.TRUE_POSITIVE:
            evidence_parts = []
            if result.reachability_probe.is_reachable:
                evidence_parts.append(f"reachable ({result.reachability_probe.http_status})")
            if result.poc_result.triggered:
                evidence_parts.append(f"PoC triggered: {result.poc_result.probe_type}")
            if result.parser_findings.has_stack_trace:
                evidence_parts.append("stack trace exposed")
            if result.middleware_findings.cors_allows_credentials_with_wildcard:
                evidence_parts.append("CORS wildcard+credentials")

            confirmed_payload = ExposureConfirmedPayload(
                job_id=job.job_id,
                tenant_id=tenant_id,
                target_url=job.target_url,
                exposure_type=job.exposure_type.value,
                final_confidence=result.final_confidence,
                evidence_summary="; ".join(evidence_parts) or "validation pipeline confirmed",
                poc_triggered=result.poc_result.triggered,
                poc_type=result.poc_result.probe_type if result.poc_result.triggered else None,
            )
            await self._publish(
                event_type=EVE_EVENT_TYPES["exposure_confirmed"],
                aggregate_id=result.result_id,
                aggregate_type="ValidationResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=confirmed_payload.model_dump(),
            )

    async def _publish(
        self,
        *,
        event_type: str,
        aggregate_id: str,
        aggregate_type: str,
        tenant_id: str,
        correlation_id: str,
        payload: dict[str, Any],
    ) -> None:
        envelope = DomainEventEnvelope(
            event_id=uuid7(),
            event_type=event_type,
            schema_version="1.0.0",
            aggregate_id=uuid.UUID(aggregate_id) if len(aggregate_id) == 36 else _NIL_UUID,
            aggregate_type=aggregate_type,
            tenant_id=uuid.UUID(tenant_id),
            correlation_id=uuid.UUID(correlation_id),
            producer_svc=_SVC_NAME,
            payload=payload,
        )
        try:
            await self._producer.produce_envelope(EVE_EXPOSURE_TOPIC, envelope)
        except Exception as exc:
            log.error(
                "eve.publisher.emit_failed",
                event_type=event_type,
                error=str(exc),
            )
