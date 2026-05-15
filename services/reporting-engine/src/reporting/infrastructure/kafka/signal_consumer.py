"""Kafka signal consumer for Reporting Engine.

Consumes:
  - acl.correlation.events  (cluster_created, exposure_prioritized,
                              remediation_generated, path_ranked)

Stores ingested records into the RE's own PG schema for report generation.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

log = structlog.get_logger(__name__)

_UPSTREAM_TOPICS = ["acl.correlation.events"]
_POLL_TIMEOUT_S = 1.0


class KafkaRESignalConsumer:
    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str = "reporting-engine",
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._group_id = group_id
        self._running = False

    def _make_consumer(self) -> object:
        from confluent_kafka import Consumer  # type: ignore[import-untyped]

        return Consumer(
            {
                "bootstrap.servers": self._bootstrap,
                "group.id": self._group_id,
                "auto.offset.reset": "latest",
                "enable.auto.commit": True,
            }
        )

    def _poll_loop(
        self,
        consumer: object,
        loop: asyncio.AbstractEventLoop,
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
        stop_event: asyncio.Event,
    ) -> None:
        from confluent_kafka import Consumer, KafkaError  # type: ignore[import-untyped]

        assert isinstance(consumer, Consumer)
        consumer.subscribe(_UPSTREAM_TOPICS)

        while not stop_event.is_set():
            msg = consumer.poll(timeout=_POLL_TIMEOUT_S)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.error("re.consumer.kafka_error", error=str(msg.error()))
                continue
            try:
                raw = json.loads(msg.value().decode("utf-8"))
                envelope = DomainEventEnvelope.model_validate(raw)
                asyncio.run_coroutine_threadsafe(callback(envelope), loop)
            except Exception as exc:
                log.warning("re.consumer.decode_error", error=str(exc))

        consumer.close()

    async def start(
        self,
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
    ) -> None:
        self._running = True
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        consumer = self._make_consumer()
        log.info("re.consumer.started", topics=_UPSTREAM_TOPICS)
        await asyncio.to_thread(self._poll_loop, consumer, loop, callback, stop_event)

    def stop(self) -> None:
        self._running = False
        log.info("re.consumer.stopped")
