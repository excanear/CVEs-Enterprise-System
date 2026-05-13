"""Dead-letter and retry topic routing for failed Kafka messages.

Retry topology per message (stamped in headers):
  retry_count == 0  → publish to <topic>.retry.1  (backoff 30 s)
  retry_count == 1  → publish to <topic>.retry.2  (backoff 5 min)
  retry_count >= 2  → publish to <topic>.dlq        (permanent, alert-triggering)

The retry topics are consumed by the same consumer group with a TTL-based
pause (enforced externally by the retry consumer sleep logic or Kafka message
timestamps + max.poll.interval.ms).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Final

from confluent_kafka import Message, Producer

from .tracing import inject_trace_context

logger = logging.getLogger(__name__)

_RETRY_SUFFIX: Final[list[str]] = [".retry.1", ".retry.2", ".dlq"]


def _next_topic(original_topic: str, retry_count: int) -> str:
    idx = min(retry_count, len(_RETRY_SUFFIX) - 1)
    return f"{original_topic}{_RETRY_SUFFIX[idx]}"


def _is_dlq(topic: str) -> bool:
    return topic.endswith(".dlq")


class RetryRouter:
    """Routes failed messages to their appropriate retry or DLQ topic.

    Uses a separate non-transactional producer for routing — retry messages
    must be decoupled from the main transaction that failed.
    """

    def __init__(self, producer: Producer) -> None:
        self._producer = producer

    @classmethod
    def from_config(
        cls,
        *,
        bootstrap_servers: str,
        client_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "RetryRouter":
        config: dict[str, Any] = {
            "bootstrap.servers": bootstrap_servers,
            "acks": "all",
            "enable.idempotence": True,
        }
        if client_id:
            config["client.id"] = client_id
        if extra:
            config.update(extra)
        return cls(Producer(config))

    def route(
        self,
        original_msg: Message,
        error: Exception,
    ) -> str:
        """Produce the message to the appropriate retry/DLQ topic.

        Returns the target topic name.
        """
        headers = dict(original_msg.headers() or [])
        retry_count = int(headers.get("retry_count", "0"))
        target_topic = _next_topic(original_msg.topic(), retry_count)

        headers["retry_count"] = str(retry_count + 1)
        headers["original_topic"] = original_msg.topic()
        headers["retry_error"] = str(error)[:1024]
        inject_trace_context(headers)

        if _is_dlq(target_topic):
            logger.error(
                "kafka_message_dlq",
                extra={
                    "original_topic": original_msg.topic(),
                    "dlq_topic": target_topic,
                    "retry_count": retry_count,
                    "error": str(error),
                },
            )
        else:
            logger.warning(
                "kafka_message_retry",
                extra={
                    "original_topic": original_msg.topic(),
                    "retry_topic": target_topic,
                    "retry_count": retry_count + 1,
                },
            )

        self._producer.produce(
            topic=target_topic,
            key=original_msg.key(),
            value=original_msg.value(),
            headers=list(headers.items()),
        )
        self._producer.poll(0)
        return target_topic
