"""Redis-based exactly-once deduplication for Kafka consumers.

Algorithm: SET NX "dedup:processed:{event_id}" 1 EX 604800 (7 days).
A True return means the event was NOT yet seen — safe to process.
A False return means the event was already processed — skip without error.

The 7-day TTL is chosen to exceed the maximum Kafka retention used by this
platform (72 h default). Adjust if retention is extended.
"""
from __future__ import annotations

import uuid
from typing import Final

import redis.asyncio as aioredis

_TTL_SECONDS: Final[int] = 604_800  # 7 days


class RedisDedup:
    """Async Redis SET NX deduplication guard for Kafka consumers."""

    def __init__(self, redis: aioredis.Redis, *, prefix: str = "dedup:processed") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, event_id: uuid.UUID) -> str:
        return f"{self._prefix}:{event_id}"

    async def is_new(self, event_id: uuid.UUID) -> bool:
        """Return True if the event_id has NOT been seen before.

        Atomically marks the event as seen with a 7-day TTL.
        Safe to call concurrently — the SET NX is atomic.
        """
        key = self._key(event_id)
        result = await self._redis.set(key, "1", nx=True, ex=_TTL_SECONDS)
        return result is True

    async def mark_processed(self, event_id: uuid.UUID) -> None:
        """Explicitly mark an event_id as processed.

        Useful when is_new() was called before processing completed and you
        need to extend or refresh the TTL.
        """
        key = self._key(event_id)
        await self._redis.set(key, "1", ex=_TTL_SECONDS)

    async def remove(self, event_id: uuid.UUID) -> None:
        """Remove the dedup record for an event_id.

        Only call this when re-processing is explicitly required (e.g. admin
        override). Never call this in normal consumer code paths.
        """
        await self._redis.delete(self._key(event_id))
