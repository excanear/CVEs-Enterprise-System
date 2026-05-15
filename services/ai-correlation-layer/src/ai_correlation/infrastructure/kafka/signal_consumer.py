"""Kafka signal consumer for AI Correlation Layer.

Consumes:
  - eve.exposure.events  (exposure.confirmed, exposure.validation_completed)
  - age.graph.events     (attack_path_discovered, exposure_propagated)

confluent-kafka Consumer is synchronous C-extension.
Poll loop runs in asyncio.to_thread; callbacks dispatched via
asyncio.run_coroutine_threadsafe (same pattern as AGE/EVE consumers).
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

log = structlog.get_logger(__name__)

_UPSTREAM_TOPICS = [
    "eve.exposure.events",
    "age.graph.events",
]

_POLL_TIMEOUT_S = 1.0


class KafkaACLSignalConsumer:
    """Polls upstream topics and forwards envelopes to the correlation service."""

    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str = "ai-correlation-layer",
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
        from confluent_kafka import Consumer, KafkaException  # type: ignore[import-untyped]

        assert isinstance(consumer, Consumer)
        consumer.subscribe(_UPSTREAM_TOPICS)

        while not stop_event.is_set():
            msg = consumer.poll(timeout=_POLL_TIMEOUT_S)
            if msg is None:
                continue
            if msg.error():
                from confluent_kafka import KafkaError  # type: ignore[import-untyped]

                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                log.error("acl.consumer.kafka_error", error=str(msg.error()))
                continue

            try:
                raw = json.loads(msg.value().decode("utf-8"))
                envelope = DomainEventEnvelope.model_validate(raw)
                asyncio.run_coroutine_threadsafe(callback(envelope), loop)
            except Exception as exc:
                log.warning("acl.consumer.decode_error", error=str(exc))

        consumer.close()

    async def start(
        self,
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
    ) -> None:
        self._running = True
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        consumer = self._make_consumer()

        log.info("acl.consumer.started", topics=_UPSTREAM_TOPICS)
        await asyncio.to_thread(
            self._poll_loop,
            consumer,
            loop,
            callback,
            stop_event,
        )

    def stop(self) -> None:
        self._running = False
        log.info("acl.consumer.stopped")
