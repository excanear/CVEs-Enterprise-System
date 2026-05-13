"""Async Kafka consumer base with exactly-once semantics via Redis dedup.

Design:
- Consumer group management delegated to Confluent librdkafka.
- After receive: check Redis dedup (is_new). If already seen, commit + skip.
- Process the message (user-supplied handler).
- Commit offset only after handler succeeds.
- OTel W3C trace context is extracted from message headers and activated.
- Errors are forwarded to the RetryRouter (retry.1 → retry.2 → DLQ).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Callable, Coroutine, Final

from confluent_kafka import Consumer, KafkaError, KafkaException, Message

from cves_event_schemas.envelope import DomainEventEnvelope

from .dedup import RedisDedup
from .tracing import extract_trace_context

logger = logging.getLogger(__name__)

MessageHandler = Callable[[DomainEventEnvelope], Coroutine[Any, Any, None]]

_POLL_TIMEOUT: Final[float] = 1.0


class BaseKafkaConsumer:
    """Async consumer loop with Redis dedup + OTel context extraction.

    Usage::

        consumer = BaseKafkaConsumer.from_config(
            bootstrap_servers="kafka:9092",
            group_id="asi-svc",
            topics=["asi.asset.events"],
            dedup=RedisDedup(redis_client),
        )
        await consumer.run(handler=my_handler)
    """

    def __init__(
        self,
        consumer: Consumer,
        dedup: RedisDedup,
        *,
        max_poll_records: int = 500,
    ) -> None:
        self._consumer = consumer
        self._dedup = dedup
        self._max_poll_records = max_poll_records
        self._running = False

    @classmethod
    def from_config(
        cls,
        *,
        bootstrap_servers: str,
        group_id: str,
        topics: list[str],
        dedup: RedisDedup,
        client_id: str | None = None,
        extra: dict[str, Any] | None = None,
        max_poll_records: int = 500,
    ) -> "BaseKafkaConsumer":
        config: dict[str, Any] = {
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
            "isolation.level": "read_committed",  # Only read committed transactional messages.
        }
        if client_id:
            config["client.id"] = client_id
        if extra:
            config.update(extra)
        c = Consumer(config)
        c.subscribe(topics)
        return cls(c, dedup, max_poll_records=max_poll_records)

    # ── Main loop ─────────────────────────────────────────────────────────

    async def run(self, handler: MessageHandler) -> None:
        """Poll Kafka indefinitely, dispatching each message to handler.

        Call stop() to initiate graceful shutdown.
        """
        self._running = True
        loop = asyncio.get_running_loop()
        try:
            while self._running:
                msg: Message | None = await loop.run_in_executor(
                    None, self._consumer.poll, _POLL_TIMEOUT
                )
                if msg is None:
                    continue
                if msg.error():
                    self._handle_kafka_error(msg)
                    continue
                await self._dispatch(msg, handler)
        finally:
            self._consumer.close()

    def stop(self) -> None:
        self._running = False

    # ── Dispatch ──────────────────────────────────────────────────────────

    async def _dispatch(self, msg: Message, handler: MessageHandler) -> None:
        try:
            envelope = self._decode(msg)
        except Exception as exc:
            logger.error(
                "kafka_decode_error",
                extra={"topic": msg.topic(), "error": str(exc)},
                exc_info=True,
            )
            self._commit(msg)  # Malformed — commit to skip.
            return

        event_id = envelope.event_id
        token = extract_trace_context(dict(msg.headers() or []))

        if not await self._dedup.is_new(event_id):
            logger.debug(
                "kafka_duplicate_skipped",
                extra={"event_id": str(event_id), "event_type": envelope.event_type},
            )
            self._commit(msg)
            return

        try:
            await handler(envelope)
        except Exception as exc:
            logger.error(
                "kafka_handler_error",
                extra={
                    "event_id": str(event_id),
                    "event_type": envelope.event_type,
                    "error": str(exc),
                },
                exc_info=True,
            )
            # Remove dedup record so retry can reprocess.
            await self._dedup.remove(event_id)
            raise  # Caller (RetryRouter) handles escalation.

        self._commit(msg)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _decode(self, msg: Message) -> DomainEventEnvelope:
        raw = json.loads(msg.value())
        return DomainEventEnvelope.model_validate(raw)

    def _commit(self, msg: Message) -> None:
        self._consumer.commit(message=msg, asynchronous=False)

    @staticmethod
    def _handle_kafka_error(msg: Message) -> None:
        err = msg.error()
        if err.code() == KafkaError._PARTITION_EOF:
            return
        logger.error(
            "kafka_poll_error",
            extra={"topic": msg.topic(), "error": str(err)},
        )
