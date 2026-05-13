from __future__ import annotations

import uuid
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.asi.asset_events import (
    ASI_ASSET_TOPIC,
    AssetDiscoveredPayload,
)
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.rf.fingerprint_events import (
    RF_FINGERPRINT_TOPIC,
    RF_EVENT_TYPES,
    APIInterceptedPayload,
    HydrationAnalysisPayload,
    SPARouteMapPayload,
    WebSocketDiscoveredPayload,
)
from cves_kafka_client.producer import BaseKafkaProducer

from runtime_analysis.domain.entities.analysis_result import AnalysisResult
from runtime_analysis.domain.entities.analysis_session import AnalysisSession

log = structlog.get_logger(__name__)

_SVC_NAME = "runtime-analysis-engine"

# Placeholder asset_id when session does not carry a pre-linked asset UUID
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


class KafkaRuntimeEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_result(
        self,
        session: AnalysisSession,
        result: AnalysisResult,
    ) -> None:
        asset_id = _NIL_UUID  # enriched by downstream RF/ASI services

        tenant_id = str(session.tenant_id)
        correlation_id = str(session.correlation_id) if session.correlation_id else str(uuid7())

        # 1. Hydration analysis event (one per session — highest-confidence fingerprint)
        for fp in result.framework_fingerprints:
            if fp.framework == "UNKNOWN":
                continue
            payload = HydrationAnalysisPayload(
                asset_id=asset_id,
                framework=fp.framework,
                version_hint=fp.version_hint,
                ssr_detected=bool(result.hydration_markers),
                hydration_delta_bytes=result.dom_snapshot.hydration_delta_bytes
                if result.dom_snapshot
                else 0,
                has_hydration_mismatch=False,
            )
            await self._publish(
                topic=RF_FINGERPRINT_TOPIC,
                event_type=RF_EVENT_TYPES["runtime_hydration_analyzed"],
                aggregate_id=result.result_id,
                aggregate_type="AnalysisResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=payload.model_dump(),
            )
            break  # one hydration event per result

        # 2. SPA routes event
        if result.spa_routes:
            has_lazy = any(bool(r.lazy_chunks) for r in result.spa_routes)
            payload = SPARouteMapPayload(
                asset_id=asset_id,
                routes=[r.path for r in result.spa_routes],
                total_routes=len(result.spa_routes),
                lazy_chunks_detected=has_lazy,
            )
            await self._publish(
                topic=RF_FINGERPRINT_TOPIC,
                event_type=RF_EVENT_TYPES["runtime_spa_routes_mapped"],
                aggregate_id=result.result_id,
                aggregate_type="AnalysisResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=payload.model_dump(),
            )

        # 3. WebSocket events (one per endpoint)
        for ws in result.websocket_endpoints:
            payload = WebSocketDiscoveredPayload(
                asset_id=asset_id,
                ws_url=ws.url,
                protocols=list(ws.protocols),
                message_count_sampled=len(ws.message_samples),
            )
            await self._publish(
                topic=RF_FINGERPRINT_TOPIC,
                event_type=RF_EVENT_TYPES["runtime_websocket_discovered"],
                aggregate_id=result.result_id,
                aggregate_type="AnalysisResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=payload.model_dump(),
            )

            # Also emit as asset discovery so ASI can correlate the WS endpoint
            ws_asset_id = uuid7()
            asset_payload = AssetDiscoveredPayload(
                asset_id=ws_asset_id,
                asset_type="URL",
                discovery_source="ACTIVE_SCAN",
                fqdn=None,
                ip_address=None,
                scan_id=None,
            )
            await self._publish(
                topic=ASI_ASSET_TOPIC,
                event_type="asi.asset.discovered",
                aggregate_id=str(ws_asset_id),
                aggregate_type="DiscoveredAsset",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=asset_payload.model_dump(),
            )

        # 4. API intercepted events (one per unique endpoint)
        for api in result.intercepted_apis:
            payload = APIInterceptedPayload(
                asset_id=asset_id,
                endpoint_url=api.url,
                method=api.method,
                is_graphql=api.is_graphql,
                status_code=api.status_code,
                param_names=list(api.params),
            )
            await self._publish(
                topic=RF_FINGERPRINT_TOPIC,
                event_type=RF_EVENT_TYPES["runtime_api_intercepted"],
                aggregate_id=result.result_id,
                aggregate_type="AnalysisResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=payload.model_dump(),
            )

    async def _publish(
        self,
        *,
        topic: str,
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
            producer_svc=_SVC_NAME,
            payload=payload,
        )
        try:
            await self._producer.produce_envelope(topic, envelope)
        except Exception as exc:
            log.error(
                "kafka_publisher.emit_failed",
                topic=topic,
                event_type=event_type,
                error=str(exc),
            )
