"""Redis-backed priority scan queue.

Data structures:
  Pending tasks  → ZADD "scanq:pending:{tenant_id}" score task_json
  In-flight      → HSET "scanq:inflight" task_id dispatch_json
  Delayed/retry  → ZADD "scanq:delayed"  score(=retry_epoch) task_json
  DLQ            → LPUSH "scanq:dlq:{task_type}" task_json

Priority score = priority_score * 1e13 - timestamp_ms
  (higher priority wins; within same priority, earlier submission wins)

A background coroutine (start_delayed_mover) polls the delayed set and
moves tasks whose retry time has elapsed into the pending queue.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Final

import redis.asyncio as aioredis

from ...domain.entities.scan_task import ScanTask, TaskStatus, TaskType
from ...domain.value_objects.scan_config import ScanConfig

logger = logging.getLogger(__name__)

_INFLIGHT_TTL: Final[int] = 3600        # 1 h — reap ghost entries
_DELAYED_POLL_INTERVAL: Final[float] = 2.0
_DLQ_MAX_LEN: Final[int] = 10_000


def _pending_key(tenant_id: uuid.UUID) -> str:
    return f"scanq:pending:{tenant_id}"


def _global_pending_key() -> str:
    return "scanq:pending:global"


def _inflight_key() -> str:
    return "scanq:inflight"


def _delayed_key() -> str:
    return "scanq:delayed"


def _dlq_key(task_type: str) -> str:
    return f"scanq:dlq:{task_type}"


def _score(priority_score: int) -> float:
    """Higher priority + earlier submission = lower score value → pops first from ZRANGE."""
    return (100 - priority_score) * 1e13 + time.time() * 1000


def _serialize(task: ScanTask) -> str:
    return json.dumps(
        {
            "task_id": str(task.task_id),
            "scan_id": str(task.scan_id),
            "tenant_id": str(task.tenant_id),
            "target": task.target,
            "task_type": task.task_type,
            "priority_score": task.priority_score,
            "config": task.config,
            "attempt_count": task.attempt_count,
            "max_attempts": task.max_attempts,
        },
        default=str,
    )


def _deserialize(raw: bytes) -> ScanTask:
    data = json.loads(raw)
    return ScanTask(
        task_id=uuid.UUID(data["task_id"]),
        scan_id=uuid.UUID(data["scan_id"]),
        tenant_id=uuid.UUID(data["tenant_id"]),
        target=data["target"],
        task_type=TaskType(data["task_type"]),
        priority_score=data["priority_score"],
        config=data.get("config", {}),
        attempt_count=data.get("attempt_count", 0),
        max_attempts=data.get("max_attempts", 3),
    )


class RedisScanQueue:
    """Priority scan queue backed by Redis sorted sets."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self._redis = redis
        self._delayed_mover: asyncio.Task | None = None

    async def enqueue(self, task: ScanTask, tenant_id: uuid.UUID) -> None:
        payload = _serialize(task)
        score = _score(task.priority_score)
        pipe = self._redis.pipeline(transaction=True)
        pipe.zadd(_pending_key(tenant_id), {payload: score})
        pipe.zadd(_global_pending_key(), {payload: score})  # global view for monitoring
        await pipe.execute()
        logger.debug("queue.enqueue", extra={"task_id": str(task.task_id), "score": score})

    async def dequeue(
        self,
        task_type: str,
        tenant_id: uuid.UUID | None = None,
        max_items: int = 1,
    ) -> list[ScanTask]:
        """Pop up to max_items highest-priority tasks from the queue."""
        key = _pending_key(tenant_id) if tenant_id else _global_pending_key()
        results: list[ScanTask] = []

        for _ in range(max_items):
            # ZPOPMIN = pop the member with the lowest score (= highest priority)
            items = await self._redis.zpopmin(key, 1)
            if not items:
                break
            payload_bytes, _ = items[0]
            try:
                task = _deserialize(payload_bytes)
            except Exception as exc:
                logger.error("queue.deserialize_error", extra={"error": str(exc)})
                continue

            # Mark in-flight
            await self._redis.hset(
                _inflight_key(),
                str(task.task_id),
                json.dumps({"tenant_id": str(tenant_id), "enqueued_at": time.time()}),
            )
            results.append(task)

        return results

    async def ack(self, task_id: uuid.UUID) -> None:
        """Remove from in-flight set after successful processing."""
        await self._redis.hdel(_inflight_key(), str(task_id))

    async def requeue_delayed(self, task: ScanTask, delay_seconds: float) -> None:
        """Schedule task to re-enter the pending queue after delay_seconds."""
        retry_at = time.time() + delay_seconds
        payload = _serialize(task)
        await self._redis.zadd(_delayed_key(), {payload: retry_at})
        logger.debug(
            "queue.delayed",
            extra={"task_id": str(task.task_id), "delay_seconds": delay_seconds},
        )

    async def move_to_dlq(self, task: ScanTask, reason: str) -> None:
        dlq = _dlq_key(task.task_type)
        entry = json.dumps(
            {
                "task_id": str(task.task_id),
                "scan_id": str(task.scan_id),
                "tenant_id": str(task.tenant_id),
                "target": task.target,
                "reason": reason,
                "attempt_count": task.attempt_count,
            },
            default=str,
        )
        pipe = self._redis.pipeline(transaction=True)
        pipe.lpush(dlq, entry)
        pipe.ltrim(dlq, 0, _DLQ_MAX_LEN - 1)
        await pipe.execute()
        logger.warning(
            "queue.dlq",
            extra={"task_id": str(task.task_id), "reason": reason},
        )

    async def queue_depth(self, tenant_id: uuid.UUID | None = None) -> dict[str, int]:
        key = _pending_key(tenant_id) if tenant_id else _global_pending_key()
        pending = await self._redis.zcard(key)
        delayed = await self._redis.zcard(_delayed_key())
        inflight = await self._redis.hlen(_inflight_key())
        return {
            "pending": pending,
            "delayed": delayed,
            "inflight": inflight,
        }

    # ── Delayed mover background task ─────────────────────────────────────

    async def start_delayed_mover(self) -> None:
        """Launch background coroutine that promotes ready delayed tasks."""
        self._delayed_mover = asyncio.create_task(
            self._delayed_move_loop(), name="scanq:delayed_mover"
        )

    async def stop(self) -> None:
        if self._delayed_mover and not self._delayed_mover.done():
            self._delayed_mover.cancel()

    async def _delayed_move_loop(self) -> None:
        logger.info("scanq.delayed_mover.started")
        while True:
            try:
                await self._promote_delayed()
            except Exception as exc:
                logger.error("scanq.delayed_mover.error", extra={"error": str(exc)})
            await asyncio.sleep(_DELAYED_POLL_INTERVAL)

    async def _promote_delayed(self) -> None:
        """Move delayed tasks whose retry time has elapsed into the pending queue."""
        now = time.time()
        items = await self._redis.zrangebyscore(
            _delayed_key(), "-inf", now, withscores=False, start=0, num=50
        )
        if not items:
            return

        pipe = self._redis.pipeline(transaction=True)
        for payload_bytes in items:
            try:
                task = _deserialize(payload_bytes)
                score = _score(task.priority_score)
                pipe.zadd(_pending_key(task.tenant_id), {payload_bytes: score})
                pipe.zadd(_global_pending_key(), {payload_bytes: score})
                pipe.zrem(_delayed_key(), payload_bytes)
            except Exception as exc:
                logger.error("scanq.promote_error", extra={"error": str(exc)})
        await pipe.execute()
        logger.debug("scanq.promoted", extra={"count": len(items)})
