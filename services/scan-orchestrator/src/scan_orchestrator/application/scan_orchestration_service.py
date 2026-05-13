"""Scan Orchestration Service — the heart of the distributed scan orchestrator.

Responsibilities:
  1. Accept SubmitScanCommand → decompose into ScanTasks → enqueue.
  2. Drive the main orchestration loop (dispatch tasks to workers).
  3. Handle task completions/failures from workers.
  4. Maintain scan-level progress and trigger terminal transitions.
  5. Publish domain events via ScanEventPublisher port.

The orchestration loop runs as a background asyncio task.
"""
from __future__ import annotations

import asyncio
import logging
import math
import random
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..domain.entities.scan import Scan, ScanPriority, ScanStatus, ScanType
from ..domain.entities.scan_task import ScanTask, TaskStatus, TaskType
from ..domain.ports import ScanEventPublisher, ScanQueue, ScanRepository, ScanTaskRepository
from ..domain.value_objects.scan_config import ScanConfig
from .commands import CancelScanCommand, RetryFailedTasksCommand, SubmitScanCommand
from .worker_pool_manager import WorkerPoolManager

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Map from ScanType to the TaskTypes it generates
_SCAN_TYPE_TO_TASKS: dict[ScanType, list[TaskType]] = {
    ScanType.NETWORK_DISCOVERY: [TaskType.ICMP_PING, TaskType.DNS_ENUMERATION],
    ScanType.PORT_SCAN: [TaskType.ICMP_PING, TaskType.PORT_SCAN, TaskType.SERVICE_DETECTION],
    ScanType.WEB_CRAWL: [TaskType.WEB_CRAWL, TaskType.BANNER_GRAB, TaskType.SSL_PROBE],
    ScanType.VULNERABILITY_PROBE: [TaskType.PORT_SCAN, TaskType.SERVICE_DETECTION, TaskType.VULN_PROBE],
    ScanType.FULL: list(TaskType),
}


class ScanOrchestrationService:
    """Application service that orchestrates the full scan lifecycle."""

    def __init__(
        self,
        *,
        scan_repo: ScanRepository,
        task_repo: ScanTaskRepository,
        scan_queue: ScanQueue,
        event_publisher: ScanEventPublisher,
        worker_pool: WorkerPoolManager,
        dispatch_concurrency: int = 20,
    ) -> None:
        self._scan_repo = scan_repo
        self._task_repo = task_repo
        self._queue = scan_queue
        self._publisher = event_publisher
        self._pool = worker_pool
        self._dispatch_concurrency = dispatch_concurrency
        self._active_tasks: dict[uuid.UUID, asyncio.Task] = {}
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────

    async def submit_scan(self, cmd: SubmitScanCommand) -> uuid.UUID:
        """Decompose command into tasks, persist, and enqueue. Returns scan_id."""
        from cves_db.types import uuid7

        scan_id = uuid7()
        scan = Scan(
            scan_id=scan_id,
            tenant_id=cmd.tenant_id,
            scan_type=cmd.scan_type,
            priority=cmd.priority,
            initiated_by=cmd.initiated_by,
            config_snapshot=cmd.config.as_dict(),
            targets=cmd.targets,
            correlation_id=cmd.correlation_id,
        )
        scan.schedule()
        await self._scan_repo.save(scan)
        await self._publisher.publish_scan_started(scan)

        tasks = self._build_tasks(scan, cmd.config)
        scan.register_tasks(len(tasks))
        await self._task_repo.save_batch(tasks)
        await self._scan_repo.save(scan)

        for task in tasks:
            await self._queue.enqueue(task, cmd.tenant_id)

        logger.info(
            "scan_submitted",
            extra={
                "scan_id": str(scan_id),
                "tenant_id": str(cmd.tenant_id),
                "task_count": len(tasks),
                "scan_type": cmd.scan_type,
            },
        )
        return scan_id

    async def cancel_scan(self, cmd: CancelScanCommand) -> None:
        scan = await self._scan_repo.get(cmd.scan_id, cmd.tenant_id)
        if scan is None:
            raise LookupError(f"Scan {cmd.scan_id} not found for tenant {cmd.tenant_id}")
        if scan.is_terminal:
            return  # idempotent
        scan.cancel(cancelled_by=cmd.cancelled_by)
        await self._scan_repo.save(scan)
        self._cancel_active_tasks_for_scan(cmd.scan_id)
        logger.info("scan_cancelled", extra={"scan_id": str(cmd.scan_id)})

    async def retry_failed_tasks(self, cmd: RetryFailedTasksCommand) -> int:
        """Re-enqueue failed tasks that still have attempts remaining. Returns count."""
        scan = await self._scan_repo.get(cmd.scan_id, cmd.tenant_id)
        if scan is None:
            raise LookupError(f"Scan {cmd.scan_id} not found")

        failed_tasks = await self._task_repo.list_by_scan(cmd.scan_id, TaskStatus.FAILED)
        retried = 0
        for task in failed_tasks:
            if task.can_retry:
                task.mark_retrying(datetime.now(tz=timezone.utc))
                task.requeue()
                await self._task_repo.update(task)
                await self._queue.enqueue(task, cmd.tenant_id)
                retried += 1
            else:
                task.move_to_dlq()
                await self._task_repo.update(task)

        logger.info(
            "scan_tasks_retried",
            extra={"scan_id": str(cmd.scan_id), "retried": retried},
        )
        return retried

    # ── Task result handlers (called by workers) ──────────────────────────

    async def on_task_completed(
        self,
        task_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        result: dict,
    ) -> None:
        task = await self._task_repo.get(task_id)
        if task is None:
            logger.warning("on_task_completed: task not found", extra={"task_id": str(task_id)})
            return
        task.complete(result)
        await self._task_repo.update(task)
        await self._scan_repo.increment_task_counter(scan_id, completed_delta=1)
        await self._check_scan_completion(scan_id, tenant_id)

    async def on_task_failed(
        self,
        task_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        error: str,
        error_code: str | None = None,
    ) -> None:
        task = await self._task_repo.get(task_id)
        if task is None:
            return
        task.fail(error, error_code)

        if task.can_retry:
            delay = self._backoff_delay(
                attempt=task.attempt_count,
                base=2.0,
                max_delay=60.0,
                jitter=True,
            )
            task.mark_retrying(datetime.now(tz=timezone.utc))
            await self._task_repo.update(task)
            task.requeue()
            await self._queue.requeue_delayed(task, delay_seconds=delay)
            await self._scan_repo.increment_task_counter(scan_id, retrying_delta=1)
        else:
            task.move_to_dlq()
            await self._task_repo.update(task)
            await self._scan_repo.increment_task_counter(scan_id, failed_delta=1)
            await self._check_scan_completion(scan_id, tenant_id)

    # ── Internal ──────────────────────────────────────────────────────────

    def _build_tasks(self, scan: Scan, config: ScanConfig) -> list[ScanTask]:
        from cves_db.types import uuid7

        task_types = _SCAN_TYPE_TO_TASKS.get(scan.scan_type, [TaskType.ICMP_PING])
        priority_score = scan.priority.as_score()
        tasks: list[ScanTask] = []

        for target in scan.targets:
            for task_type in task_types:
                tasks.append(
                    ScanTask(
                        task_id=uuid7(),
                        scan_id=scan.scan_id,
                        tenant_id=scan.tenant_id,
                        target=target,
                        task_type=task_type,
                        priority_score=priority_score,
                        config=config.as_dict(),
                        max_attempts=config.max_retries + 1,
                    )
                )
        return tasks

    async def _check_scan_completion(
        self, scan_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> None:
        scan = await self._scan_repo.get(scan_id, tenant_id)
        if scan is None or scan.is_terminal:
            return

        done = scan.tasks_completed + scan.tasks_failed
        if done >= scan.tasks_total and scan.tasks_retrying == 0:
            if scan.tasks_failed == scan.tasks_total:
                scan.fail("All tasks failed")
                await self._publisher.publish_scan_failed(scan)
            else:
                scan.complete()
                await self._publisher.publish_scan_completed(scan)
            await self._scan_repo.save(scan)

    def _cancel_active_tasks_for_scan(self, scan_id: uuid.UUID) -> None:
        for task_id, asyncio_task in list(self._active_tasks.items()):
            # Tag is stored in asyncio_task.get_name() as "scan:{scan_id}:{task_id}"
            if f"scan:{scan_id}:" in asyncio_task.get_name():
                asyncio_task.cancel()
                self._active_tasks.pop(task_id, None)

    @staticmethod
    def _backoff_delay(
        attempt: int,
        base: float,
        max_delay: float,
        jitter: bool,
    ) -> float:
        delay = min(base ** attempt, max_delay)
        if jitter:
            delay *= random.uniform(0.75, 1.25)  # noqa: S311 — non-crypto random is fine for jitter
        return delay
