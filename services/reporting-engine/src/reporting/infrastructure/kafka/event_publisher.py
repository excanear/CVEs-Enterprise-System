"""Kafka event publisher for Reporting Engine.

Publishes to topic: re.report.events
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.re.re_events import RE_REPORT_TOPIC, RE_EVENT_TYPES, ReportGeneratedPayload
from cves_kafka_client.producer import BaseKafkaProducer

from reporting.domain.entities.report import Report

log = structlog.get_logger(__name__)

_SVC_NAME = "reporting-engine"
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def _safe_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return _NIL_UUID


class KafkaREEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_report_generated(self, report: Report) -> None:
        payload = ReportGeneratedPayload(
            report_id=report.report_id,
            tenant_id=report.tenant_id,
            report_type=report.report_type.value,
            report_format=report.report_format.value,
            finding_count=report.finding_count,
            generated_at=(report.generated_at or datetime.now(UTC)).isoformat(),
        )
        envelope = DomainEventEnvelope(
            event_id=uuid7(),
            event_type=RE_EVENT_TYPES["report_generated"],
            schema_version="1.0.0",
            aggregate_id=_safe_uuid(report.report_id),
            aggregate_type="Report",
            tenant_id=_safe_uuid(report.tenant_id),
            correlation_id=uuid7(),
            producer_svc=_SVC_NAME,
            payload=payload.model_dump(),
        )
        try:
            await self._producer.produce_envelope(RE_REPORT_TOPIC, envelope)
        except Exception as exc:
            log.warning("re.publisher.produce_failed", error=str(exc))
