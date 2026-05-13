"""Kafka signal consumer for Asset Graph Engine.

Consumes upstream domain events from 4 topics:
  - asi.asset.events       (Asset Surfaces Intelligence)
  - rf.fingerprint.events  (Runtime Fingerprinting / RAE)
  - jsi.js.events          (JS Intelligence Engine)
  - eve.exposure.events    (Exposure Validation Engine)

confluent-kafka Consumer is synchronous C-extension.
Poll loop runs in asyncio.to_thread; callbacks dispatched via
asyncio.run_coroutine_threadsafe (same pattern as EVE consumer).
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

log = structlog.get_logger(__name__)

_UPSTREAM_TOPICS = [
    "asi.asset.events",
    "rf.fingerprint.events",
    "jsi.js.events",
    "eve.exposure.events",
]

_POLL_TIMEOUT_S = 1.0


class KafkaGraphSignalConsumer:
    """Polls upstream topics and forwards envelopes to the AGE ingestion service."""

    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str = "asset-graph-engine",
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
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Synchronous polling loop — executed in a background thread."""
        consumer = self._make_consumer()
        consumer.subscribe(_UPSTREAM_TOPICS)
        log.info("age.consumer.started", topics=_UPSTREAM_TOPICS)

        while self._running:
            msg = consumer.poll(timeout=_POLL_TIMEOUT_S)
            if msg is None:
                continue
            if msg.error():
                log.warning("age.consumer.poll_error", error=str(msg.error()))
                continue
            try:
                data = json.loads(msg.value())
                envelope = DomainEventEnvelope(**data)
                asyncio.run_coroutine_threadsafe(
                    callback(envelope), loop
                ).result(timeout=30)
            except Exception as exc:
                log.error("age.consumer.dispatch_error", error=str(exc))

        consumer.close()
        log.info("age.consumer.stopped")

    async def start_consuming(
        self,
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
    ) -> None:
        """Start polling loop in a background thread. Non-blocking."""
        self._running = True
        loop = asyncio.get_running_loop()
        await asyncio.to_thread(self._poll_loop, callback, loop)

    async def stop(self) -> None:
        self._running = False
