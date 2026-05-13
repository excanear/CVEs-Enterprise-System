from __future__ import annotations

import uuid
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.jsi.js_events import (
    JSI_JS_TOPIC,
    JSI_EVENT_TYPES,
    JSBundleAnalyzedPayload,
    JSDependencyGraphBuiltPayload,
    JSRoutesDiscoveredPayload,
    RouteEntry,
)
from cves_kafka_client.producer import BaseKafkaProducer

from js_intelligence.domain.entities.js_analysis_job import JSAnalysisJob
from js_intelligence.domain.entities.js_intelligence_result import JSIntelligenceResult

log = structlog.get_logger(__name__)

_SVC_NAME = "js-intelligence-engine"
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


class KafkaJSIntelligenceEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_result(
        self,
        job: JSAnalysisJob,
        result: JSIntelligenceResult,
    ) -> None:
        tenant_id = str(job.tenant_id)
        correlation_id = str(job.correlation_id) if job.correlation_id else str(uuid7())
        job_id_uuid = uuid.UUID(job.job_id)
        asset_id = _NIL_UUID  # enriched downstream by ASI/RF services

        # 1. One JSBundleAnalyzedPayload per bundle
        for bundle in result.bundles:
            payload = JSBundleAnalyzedPayload(
                job_id=job_id_uuid,
                asset_id=asset_id,
                bundle_url=bundle.url,
                content_hash=bundle.content_hash,
                size_bytes=bundle.size_bytes,
                is_minified=bundle.is_minified,
                bundler=bundle.bundler,
                chunk_id=bundle.chunk_id,
                source_map_url=bundle.source_map_url,
                has_source_map=bool(bundle.source_map_url),
            )
            await self._publish(
                topic=JSI_JS_TOPIC,
                event_type=JSI_EVENT_TYPES["js_bundle_analyzed"],
                aggregate_id=result.result_id,
                aggregate_type="JSIntelligenceResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=payload.model_dump(),
            )

        # 2. JSRoutesDiscoveredPayload — one per job
        if result.hidden_routes:
            router_types = {r.router_type for r in result.hidden_routes}
            dominant_router = max(router_types, key=lambda rt: sum(
                1 for r in result.hidden_routes if r.router_type == rt
            ))
            routes_payload = JSRoutesDiscoveredPayload(
                job_id=job_id_uuid,
                asset_id=asset_id,
                target_url=job.target_url,
                routes=[
                    RouteEntry(
                        path=r.path,
                        router_type=r.router_type,
                        component_hint=r.component_hint,
                        confidence=r.confidence,
                        discovered_in_chunk=r.discovered_in_chunk,
                        lazy_chunks=list(r.lazy_chunks),
                    )
                    for r in result.hidden_routes
                ],
                total_routes=len(result.hidden_routes),
                bundler=result.bundler_signature.bundler,
                router_type_detected=dominant_router,
            )
            await self._publish(
                topic=JSI_JS_TOPIC,
                event_type=JSI_EVENT_TYPES["js_routes_discovered"],
                aggregate_id=result.result_id,
                aggregate_type="JSIntelligenceResult",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                payload=routes_payload.model_dump(),
            )

        # 3. JSDependencyGraphBuiltPayload — one per job
        graph = result.dependency_graph
        graph_payload = JSDependencyGraphBuiltPayload(
            job_id=job_id_uuid,
            asset_id=asset_id,
            target_url=job.target_url,
            node_count=graph.node_count,
            edge_count=graph.edge_count,
            has_cycles=graph.has_cycles,
            entry_points=graph.entry_points,
            bundler=result.bundler_signature.bundler,
            chunk_count=result.bundler_signature.chunk_count,
        )
        await self._publish(
            topic=JSI_JS_TOPIC,
            event_type=JSI_EVENT_TYPES["js_dependency_graph_built"],
            aggregate_id=result.result_id,
            aggregate_type="JSIntelligenceResult",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            payload=graph_payload.model_dump(),
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
                "kafka_jsi_publisher.emit_failed",
                topic=topic,
                event_type=event_type,
                error=str(exc),
            )
