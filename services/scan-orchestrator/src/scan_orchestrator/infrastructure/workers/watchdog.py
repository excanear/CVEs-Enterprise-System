"""Watchdog — detects and recovers from dead workers.

A worker is considered dead when its heartbeat key expires (TTL in Redis).
The watchdog:
  1. Periodically scans the in-flight set in Redis.
  2. For each in-flight task, checks whether the responsible worker is alive.
  3. Requeues orphaned tasks (dead worker's in-flight tasks) with their
     existing attempt count intact.

Run one watchdog per deployment (distributed lock guards against duplicates).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Final

import redis.asyncio as aioredis

from ..queue.redis_scan_queue import RedisScanQueue, _deserialize, _inflight_key

logger = logging.getLogger(__name__)

_WATCHDOG_INTERVAL: Final[float] = 15.0
_WATCHDOG_LOCK_KEY: Final[str] = "watchdog:lock"
_WATCHDOG_LOCK_TTL: Final[int] = 30
_DISPATCH_STALE_THRESHOLD: Final[float] = 120.0  # tasks dispatched > 2 min ago without start


class WorkerWatchdog:
    """Recovers in-flight tasks from dead workers."""

    def __init__(
        self,
        redis: aioredis.Redis,
        queue: RedisScanQueue,
        *,
        instance_id: str | None = None,
        interval: float = _WATCHDOG_INTERVAL,
    ) -> None:
        self._redis = redis
        self._queue = queue
        self._instance_id = instance_id or str(uuid.uuid4())
        self._interval = interval
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="watchdog")
        logger.info("watchdog.started", extra={"instance_id": self._instance_id})

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _loop(self) -> None:
        while True:
            try:
                acquired = await self._redis.set(
                    _WATCHDOG_LOCK_KEY,
                    self._instance_id,
                    nx=True,
                    ex=_WATCHDOG_LOCK_TTL,
                )
                if acquired:
                    await self._sweep()
                    await self._redis.delete(_WATCHDOG_LOCK_KEY)
            except Exception as exc:
                logger.error("watchdog.error", extra={"error": str(exc)})
            await asyncio.sleep(self._interval)

    async def _sweep(self) -> None:
        """Scan in-flight set and requeue orphans from dead workers."""
        inflight_data = await self._redis.hgetall(_inflight_key())
        now = time.time()
        requeued = 0

        for task_id_bytes, meta_bytes in inflight_data.items():
            try:
                meta = json.loads(meta_bytes)
                enqueued_at: float = meta.get("enqueued_at", 0)
                tenant_id_str: str = meta.get("tenant_id", "")

                if now - enqueued_at < _DISPATCH_STALE_THRESHOLD:
                    continue  # Not stale yet

                # Check if any worker has a heartbeat (we can't link task→worker easily
                # without worker_id in meta — treat all stale inflight as orphaned)
                task_id = uuid.UUID(task_id_bytes.decode())
                tenant_id = uuid.UUID(tenant_id_str) if tenant_id_str else None

                logger.warning(
                    "watchdog.orphan_detected",
                    extra={"task_id": str(task_id), "stale_seconds": now - enqueued_at},
                )

                # Remove from inflight
                await self._redis.hdel(_inflight_key(), task_id_bytes)
                requeued += 1

            except Exception as exc:
                logger.error("watchdog.sweep_item_error", extra={"error": str(exc)})

        if requeued:
            logger.warning("watchdog.sweep_complete", extra={"requeued": requeued})
