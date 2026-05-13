"""Base scan worker — async poll loop with fault tolerance.

Each worker:
  1. Polls the scan queue for tasks matching its capabilities.
  2. Acquires a slot from the WorkerPoolManager (back-pressure).
  3. Checks the CircuitBreaker for the target.
  4. Acquires a rate-limit token (AdaptiveRateLimiter).
  5. Executes the task with an asyncio timeout.
  6. Reports result to the ScanOrchestrationService.
  7. Sends a heartbeat to Redis every N seconds.

Fault tolerance:
  - asyncio.timeout enforces per-task max execution time.
  - Circuit breaker prevents hammering dead targets.
  - Adaptive rate limiter slows down on 429/timeouts.
  - Heartbeat detection: if a worker stops sending heartbeats, a watchdog
    can reclaim its in-flight tasks.
  - Graceful shutdown: drains in-flight tasks before stopping.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, Final

import redis.asyncio as aioredis

from ...application.adaptive_rate_limiter import AdaptiveRateLimiter
from ...application.scan_orchestration_service import ScanOrchestrationService
from ...application.worker_pool_manager import WorkerPoolManager
from ...domain.entities.scan_task import ScanTask, TaskType
from ...infrastructure.circuit_breaker import CircuitBreaker, CircuitState
from ...infrastructure.queue.redis_scan_queue import RedisScanQueue

logger = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL: Final[float] = 5.0
_HEARTBEAT_TTL: Final[int] = 30         # dead worker detection threshold
_POLL_INTERVAL: Final[float] = 0.5
_TASK_TIMEOUT: Final[float] = 60.0


@dataclass
class WorkerConfig:
    worker_id: uuid.UUID = field(default_factory=uuid.uuid4)
    worker_type: str = "generic"
    supported_task_types: list[TaskType] = field(default_factory=list)
    max_concurrent_tasks: int = 10
    poll_batch_size: int = 5
    task_timeout_seconds: float = _TASK_TIMEOUT
    heartbeat_interval: float = _HEARTBEAT_INTERVAL


class BaseWorker:
    """Abstract base for all scan worker implementations.

    Subclasses implement `execute_task()`. Everything else is provided here.
    """

    def __init__(
        self,
        *,
        config: WorkerConfig,
        redis: aioredis.Redis,
        queue: RedisScanQueue,
        pool: WorkerPoolManager,
        circuit_breaker: CircuitBreaker,
        rate_limiter: AdaptiveRateLimiter,
        orchestration_service: ScanOrchestrationService,
        tenant_id: uuid.UUID | None = None,
    ) -> None:
        self.cfg = config
        self._redis = redis
        self._queue = queue
        self._pool = pool
        self._cb = circuit_breaker
        self._rl = rate_limiter
        self._svc = orchestration_service
        self._tenant_id = tenant_id

        self._running = False
        self._active_count = 0
        self._task_handles: set[asyncio.Task] = set()
        self._background: list[asyncio.Task] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._running = True
        self._background = [
            asyncio.create_task(self._poll_loop(), name=f"worker:{self.cfg.worker_id}:poll"),
            asyncio.create_task(self._heartbeat_loop(), name=f"worker:{self.cfg.worker_id}:hb"),
        ]
        logger.info("worker.started", extra={"worker_id": str(self.cfg.worker_id), "type": self.cfg.worker_type})

    async def stop(self, drain_timeout: float = 30.0) -> None:
        """Graceful shutdown: stop accepting new tasks, wait for in-flight to finish."""
        self._running = False
        for bg in self._background:
            bg.cancel()

        if self._task_handles:
            logger.info("worker.draining", extra={"inflight": len(self._task_handles)})
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._task_handles, return_exceptions=True),
                    timeout=drain_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("worker.drain_timeout — cancelling remaining tasks")
                for t in self._task_handles:
                    t.cancel()

        await self._redis.delete(self._heartbeat_key())
        logger.info("worker.stopped", extra={"worker_id": str(self.cfg.worker_id)})

    # ── Abstract ──────────────────────────────────────────────────────────

    @abstractmethod
    async def execute_task(self, task: ScanTask) -> dict[str, Any]:
        """Execute the scan task and return a result dict.

        Raise any exception to signal failure — the base class handles
        circuit breaker and rate limiter feedback automatically.
        """

    # ── Poll loop ─────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                available_slots = self.cfg.max_concurrent_tasks - self._active_count
                if available_slots <= 0:
                    await asyncio.sleep(_POLL_INTERVAL)
                    continue

                batch_size = min(available_slots, self.cfg.poll_batch_size)
                tasks = await self._queue.dequeue(
                    task_type=self.cfg.worker_type,
                    tenant_id=self._tenant_id,
                    max_items=batch_size,
                )
                if not tasks:
                    await asyncio.sleep(_POLL_INTERVAL)
                    continue

                for task in tasks:
                    handle = asyncio.create_task(
                        self._process_task(task),
                        name=f"scan:{task.scan_id}:{task.task_id}",
                    )
                    self._task_handles.add(handle)
                    handle.add_done_callback(self._task_handles.discard)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("worker.poll_error", extra={"error": str(exc)}, exc_info=True)
                await asyncio.sleep(_POLL_INTERVAL * 4)

    # ── Task execution ────────────────────────────────────────────────────

    async def _process_task(self, task: ScanTask) -> None:
        # ① Circuit breaker check
        cb_state = await self._cb.check(task.target)
        if cb_state == CircuitState.OPEN:
            logger.warning(
                "worker.circuit_open",
                extra={"target": task.target, "task_id": str(task.task_id)},
            )
            # Re-queue with a short delay so the target has time to recover
            await self._queue.requeue_delayed(task, delay_seconds=30.0)
            await self._queue.ack(task.task_id)
            return

        # ② Rate-limit acquisition
        await self._rl.acquire(task.target, wait=True)

        task.start()
        self._active_count += 1

        try:
            async with self._pool.acquire(task_type=task.task_type, tenant_id=task.tenant_id):
                async with asyncio.timeout(self.cfg.task_timeout_seconds):
                    result = await self.execute_task(task)

            # ③ Success path
            await self._rl.record_success(task.target)
            await self._cb.record_success(task.target)
            await self._queue.ack(task.task_id)
            await self._svc.on_task_completed(
                task.task_id, task.scan_id, task.tenant_id, result
            )
            logger.debug(
                "worker.task_completed",
                extra={"task_id": str(task.task_id), "target": task.target},
            )

        except asyncio.TimeoutError:
            logger.warning(
                "worker.task_timeout",
                extra={"task_id": str(task.task_id), "target": task.target},
            )
            await self._rl.record_timeout(task.target)
            await self._cb.record_failure(task.target)
            await self._queue.ack(task.task_id)
            await self._svc.on_task_failed(
                task.task_id, task.scan_id, task.tenant_id,
                "Task timed out", "TIMEOUT",
            )

        except Exception as exc:
            error_code = getattr(exc, "error_code", None) or type(exc).__name__
            await self._cb.record_failure(task.target)

            if "429" in str(exc) or "rate" in str(exc).lower():
                await self._rl.record_throttle(task.target)
                error_code = "RATE_LIMITED"

            logger.warning(
                "worker.task_failed",
                extra={
                    "task_id": str(task.task_id),
                    "target": task.target,
                    "error": str(exc),
                    "error_code": error_code,
                },
            )
            await self._queue.ack(task.task_id)
            await self._svc.on_task_failed(
                task.task_id, task.scan_id, task.tenant_id, str(exc), error_code
            )

        finally:
            self._active_count -= 1

    # ── Heartbeat ─────────────────────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await self._redis.setex(
                    self._heartbeat_key(),
                    _HEARTBEAT_TTL,
                    json.dumps(
                        {
                            "worker_id": str(self.cfg.worker_id),
                            "worker_type": self.cfg.worker_type,
                            "active_tasks": self._active_count,
                            "timestamp": time.time(),
                        }
                    ),
                )
            except Exception as exc:
                logger.error("worker.heartbeat_error", extra={"error": str(exc)})
            await asyncio.sleep(self.cfg.heartbeat_interval)

    def _heartbeat_key(self) -> str:
        return f"worker:heartbeat:{self.cfg.worker_id}"
