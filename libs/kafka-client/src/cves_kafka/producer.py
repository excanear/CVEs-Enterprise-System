"""Transactional Kafka producer with Outbox support.

Design:
- Each producer instance owns a single transactional.id (per-partition, per-service).
- Exactly-once delivery via idempotent producer + Kafka transactions.
- Events are encoded as JSON (Avro optional — hook in schemas/registry_client.py).
- OTel W3C trace context is injected into message headers by cves_kafka.tracing.
- The Outbox batch flow: collect OutboxEntry rows → publish in Kafka tx → mark published.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Final

from confluent_kafka import KafkaException, Producer

from cves_event_schemas.envelope import DomainEventEnvelope

from .tracing import inject_trace_context

logger = logging.getLogger(__name__)

_DELIVERY_TIMEOUT_MS: Final[int] = 30_000


class BaseKafkaProducer:
    """Thread-safe transactional Kafka producer.

    Usage::

        producer = BaseKafkaProducer.from_config(
            bootstrap_servers="kafka:9092",
            transactional_id="asi-svc-1",
        )
        async with producer.transaction():
            producer.produce_envelope(envelope)
    """

    def __init__(self, producer: Producer) -> None:
        self._producer = producer
        self._initialized = False

    @classmethod
    def from_config(
        cls,
        *,
        bootstrap_servers: str,
        transactional_id: str,
        client_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "BaseKafkaProducer":
        config: dict[str, Any] = {
            "bootstrap.servers": bootstrap_servers,
            "enable.idempotence": True,
            "acks": "all",
            "transactional.id": transactional_id,
            "delivery.timeout.ms": _DELIVERY_TIMEOUT_MS,
        }
        if client_id:
            config["client.id"] = client_id
        if extra:
            config.update(extra)
        p = Producer(config)
        return cls(p)

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def init_transactions(self) -> None:
        """Must be called once before the first transaction."""
        if not self._initialized:
            self._producer.init_transactions()
            self._initialized = True

    def begin_transaction(self) -> None:
        self._producer.begin_transaction()

    def commit_transaction(self) -> None:
        self._producer.commit_transaction()

    def abort_transaction(self) -> None:
        try:
            self._producer.abort_transaction()
        except KafkaException:
            logger.warning("abort_transaction raised — likely already aborted or not started.")

    def flush(self, timeout: float = 10.0) -> int:
        return self._producer.flush(timeout=timeout)

    # ── Produce ───────────────────────────────────────────────────────────

    def produce_envelope(
        self,
        topic: str,
        envelope: DomainEventEnvelope,
        *,
        key: str | None = None,
    ) -> None:
        """Serialise and produce a DomainEventEnvelope within the current transaction."""
        headers = envelope.to_kafka_headers()
        inject_trace_context(headers)

        payload_bytes = json.dumps(
            {
                "event_id": str(envelope.event_id),
                "event_type": envelope.event_type,
                "schema_version": envelope.schema_version,
                "aggregate_id": str(envelope.aggregate_id),
                "aggregate_type": envelope.aggregate_type,
                "tenant_id": str(envelope.tenant_id),
                "correlation_id": str(envelope.correlation_id),
                "causation_id": str(envelope.causation_id) if envelope.causation_id else None,
                "timestamp": envelope.timestamp,
                "producer_svc": envelope.producer_svc,
                "payload": envelope.payload,
                "metadata": envelope.metadata,
            },
            default=str,
        ).encode()

        kafka_key = (key or str(envelope.tenant_id)).encode()

        self._producer.produce(
            topic=topic,
            key=kafka_key,
            value=payload_bytes,
            headers=headers,
            on_delivery=self._on_delivery,
        )

    def produce_outbox_row(self, topic: str, row: dict[str, Any]) -> None:
        """Produce a raw outbox row dict (from OutboxEntry columns).

        Called by the Outbox poller — not for direct use in services.
        """
        headers: dict[str, str] = {
            "event_type": row.get("event_type", ""),
            "schema_version": row.get("schema_version", "1.0.0"),
            "correlation_id": str(row.get("correlation_id", "")),
            "tenant_id": str(row.get("tenant_id", "")),
        }
        if row.get("causation_id"):
            headers["causation_id"] = str(row["causation_id"])
        inject_trace_context(headers)

        self._producer.produce(
            topic=topic,
            key=(row.get("kafka_key") or str(row.get("tenant_id", ""))).encode(),
            value=json.dumps(row["payload"], default=str).encode(),
            headers=headers,
            on_delivery=self._on_delivery,
        )

    # ── Delivery report ───────────────────────────────────────────────────

    @staticmethod
    def _on_delivery(err: Any, msg: Any) -> None:
        if err:
            logger.error(
                "kafka_delivery_failed",
                extra={"topic": msg.topic(), "partition": msg.partition(), "error": str(err)},
            )
        else:
            logger.debug(
                "kafka_delivered",
                extra={
                    "topic": msg.topic(),
                    "partition": msg.partition(),
                    "offset": msg.offset(),
                },
            )
