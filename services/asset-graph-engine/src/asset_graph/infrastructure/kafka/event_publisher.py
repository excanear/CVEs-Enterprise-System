"""Kafka event publisher for Asset Graph Engine.

Publishes to topic: age.graph.events
Event types: node_upserted, edge_upserted, attack_path_discovered, exposure_propagated
"""
from __future__ import annotations

import uuid
from typing import Any

import structlog

from cves_db.types import uuid7
from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.age.age_events import (
    AGE_GRAPH_TOPIC,
    AGE_EVENT_TYPES,
    AttackPathDiscoveredPayload,
    EdgeUpsertedPayload,
    ExposurePropagatedPayload,
    NodeUpsertedPayload,
)
from cves_kafka_client.producer import BaseKafkaProducer

from asset_graph.domain.entities.graph_node import GraphNode
from asset_graph.domain.value_objects.attack_path import AttackPath
from asset_graph.domain.value_objects.propagation_result import ExposurePropagation

log = structlog.get_logger(__name__)

_SVC_NAME = "asset-graph-engine"
_NIL_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")


class KafkaAGEEventPublisher:
    def __init__(self, producer: BaseKafkaProducer) -> None:
        self._producer = producer

    async def publish_node_upserted(self, node: GraphNode) -> None:
        payload = NodeUpsertedPayload(
            node_id=node.node_id,
            tenant_id=node.tenant_id,
            label=node.label.value,
            url=node.properties.get("url"),
            host=node.properties.get("host"),
            properties=node.properties,
        )
        await self._publish(
            event_type=AGE_EVENT_TYPES["node_upserted"],
            aggregate_id=node.node_id,
            aggregate_type="GraphNode",
            tenant_id=node.tenant_id,
            payload=payload.model_dump(),
        )

    async def publish_attack_path(self, path: AttackPath, tenant_id: str) -> None:
        payload = AttackPathDiscoveredPayload(
            tenant_id=tenant_id,
            source_endpoint_id=path.source_endpoint_id,
            target_asset_id=path.target_asset_id,
            hops=path.hops,
            path_node_ids=path.node_ids,
            risk_score=path.risk_score,
        )
        await self._publish(
            event_type=AGE_EVENT_TYPES["attack_path_discovered"],
            aggregate_id=path.source_endpoint_id,
            aggregate_type="AttackPath",
            tenant_id=tenant_id,
            payload=payload.model_dump(),
        )

    async def publish_propagation(self, propagation: ExposurePropagation) -> None:
        payload = ExposurePropagatedPayload(
            tenant_id=propagation.tenant_id,
            origin_endpoint_id=propagation.origin_endpoint_id,
            affected_asset_ids=[h.asset_id for h in propagation.affected_assets],
            propagation_depth=propagation.propagation_depth,
            max_hops_reached=propagation.max_hops_reached,
        )
        await self._publish(
            event_type=AGE_EVENT_TYPES["exposure_propagated"],
            aggregate_id=propagation.origin_endpoint_id,
            aggregate_type="ExposurePropagation",
            tenant_id=propagation.tenant_id,
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
        try:
            _agg_uuid = _safe_uuid(aggregate_id)
            _ten_uuid = _safe_uuid(tenant_id)
        except Exception:
            return

        envelope = DomainEventEnvelope(
            event_id=uuid7(),
            event_type=event_type,
            schema_version="1.0.0",
            aggregate_id=_agg_uuid,
            aggregate_type=aggregate_type,
            tenant_id=_ten_uuid,
            correlation_id=uuid7(),
            producer_svc=_SVC_NAME,
            payload=payload,
        )
        try:
            await self._producer.produce_envelope(AGE_GRAPH_TOPIC, envelope)
        except Exception as exc:
            log.warning("age.publisher.produce_failed", event_type=event_type, error=str(exc))


def _safe_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return _NIL_UUID
