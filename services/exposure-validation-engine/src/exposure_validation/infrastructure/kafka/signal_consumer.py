"""Kafka signal consumer — polls upstream topics and routes events to the EVE pipeline.

Architecture note:
  confluent-kafka's Consumer is a synchronous C-extension library.
  We run the polling loop inside `asyncio.to_thread` so it does not block
  the event loop. The callback is an async coroutine dispatched via
  `asyncio.run_coroutine_threadsafe`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

log = structlog.get_logger(__name__)

# Topics produced by upstream engines that EVE cares about
_UPSTREAM_TOPICS = [
    "jsi.js.events",
    "rf.fingerprint.events",
    "asi.asset.events",
]

_POLL_TIMEOUT_S = 1.0  # confluent-kafka poll timeout


class KafkaSignalConsumer:
    """Consumes upstream domain events and forwards them to the EVE pipeline."""

    def __init__(
        self,
        bootstrap_servers: str,
        group_id: str = "exposure-validation-engine",
    ) -> None:
        self._bootstrap = bootstrap_servers
        self._group_id = group_id
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None

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
        """Synchronous polling loop — runs in a thread."""
        consumer = self._make_consumer()
        consumer.subscribe(_UPSTREAM_TOPICS)
        log.info("eve.consumer.started", topics=_UPSTREAM_TOPICS)

        while self._running:
            msg = consumer.poll(timeout=_POLL_TIMEOUT_S)
            if msg is None:
                continue
            if msg.error():
                log.warning("eve.consumer.poll_error", error=str(msg.error()))
                continue
            try:
                data = json.loads(msg.value())
                envelope = DomainEventEnvelope(**data)
                asyncio.run_coroutine_threadsafe(callback(envelope), loop).result(timeout=30)
            except Exception as exc:
                log.error("eve.consumer.dispatch_error", error=str(exc))

        consumer.close()
        log.info("eve.consumer.stopped")

    async def start_consuming(
        self,
        callback: Callable[[DomainEventEnvelope], Awaitable[None]],
    ) -> None:
        """Start polling loop in a background thread. Non-blocking — returns immediately."""
        self._running = True
        self._loop = asyncio.get_running_loop()
        loop = self._loop
        await asyncio.to_thread(self._poll_loop, callback, loop)

    async def stop(self) -> None:
        self._running = False
