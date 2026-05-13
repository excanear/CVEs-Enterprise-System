"""Kafka event publisher for Discovery Engine domain events.

Maps domain entities to ASI event schema payloads and publishes to the
canonical `asi.asset.events` topic via the transactional BaseKafkaProducer.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from cves_db.types import uuid7
from cves_event_schemas.asi.asset_events import (
    ASI_ASSET_TOPIC,
    AssetDiscoveredPayload,
    CertificateExpiringSoonPayload,
    ScanCompletedPayload,
    ScanFailedPayload,
)
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_kafka.producer import BaseKafkaProducer

from ...domain.entities.discovered_asset import AssetType, DiscoveredAsset
from ...domain.entities.discovery_job import DiscoveryJob
from ...domain.value_objects.certificate import Certificate

logger = logging.getLogger(__name__)

_SVC_NAME = "discovery-engine"


class KafkaDiscoveryEventPublisher:
    """Publishes discovery domain events to Kafka ASI topic."""

    def __init__(
        self,
        producer: BaseKafkaProducer,
        *,
        service_name: str = _SVC_NAME,
    ) -> None:
        self._producer = producer
        self._svc = service_name

    async def publish_asset_discovered(
        self, asset: DiscoveredAsset, job: DiscoveryJob
    ) -> None:
        ip_address: str | None = None
        fqdn: str | None = None

        if asset.asset_type == AssetType.HOST:
            ip_address = asset.value
        else:
            fqdn = asset.value

        payload = AssetDiscoveredPayload(
            asset_id=asset.asset_id,
            asset_type=asset.asi_asset_type,          # mapped literal
            discovery_source=asset.asi_discovery_source,  # mapped literal
            ip_address=ip_address,
            fqdn=fqdn,
            scan_id=job.job_id,
        )
        await self._publish(
            event_type="asi.asset.discovered",
            aggregate_id=str(asset.asset_id),
            aggregate_type="DiscoveredAsset",
            tenant_id=str(asset.tenant_id),
            correlation_id=str(asset.correlation_id or job.correlation_id or uuid7()),
            payload=payload.model_dump(),
        )

    async def publish_cert_expiring_soon(
        self,
        asset: DiscoveredAsset,
        cert: Certificate,
    ) -> None:
        payload = CertificateExpiringSoonPayload(
            asset_id=asset.asset_id,
            fqdn=cert.subject_cn,
            days_to_expiry=cert.days_to_expiry,
            fingerprint_sha256=cert.serial,
        )
        await self._publish(
            event_type="asi.domain.certificate_expiring",
            aggregate_id=str(asset.asset_id),
            aggregate_type="Certificate",
            tenant_id=str(asset.tenant_id),
            correlation_id=str(asset.correlation_id or uuid7()),
            payload=payload.model_dump(),
        )

    async def publish_job_completed(self, job: DiscoveryJob) -> None:
        payload = ScanCompletedPayload(
            scan_id=job.job_id,
            scan_type="DISCOVERY",
            total_targets=len(job.scope_domains),
            discovered=job.assets_found,
            updated=0,
            errors=0,
            duration_seconds=job.duration_seconds or 0.0,
            discovered_asset_ids=[],
            updated_asset_ids=[],
        )
        await self._publish(
            event_type="asi.scan.completed",
            aggregate_id=str(job.job_id),
            aggregate_type="DiscoveryJob",
            tenant_id=str(job.tenant_id),
            correlation_id=str(job.correlation_id or uuid7()),
            payload=payload.model_dump(),
        )

    async def publish_job_failed(self, job: DiscoveryJob) -> None:
        payload = ScanFailedPayload(
            scan_id=job.job_id,
            error_code="DISCOVERY_FAILED",
            error_message=job.failure_reason or "unknown",
            retryable=True,
        )
        await self._publish(
            event_type="asi.scan.failed",
            aggregate_id=str(job.job_id),
            aggregate_type="DiscoveryJob",
            tenant_id=str(job.tenant_id),
            correlation_id=str(job.correlation_id or uuid7()),
            payload=payload.model_dump(),
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
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            producer_svc=self._svc,
            payload=payload,
        )
        await self._producer.produce_envelope(ASI_ASSET_TOPIC, envelope)
