"""Repository and scheduler ports (typing.Protocol — zero infrastructure imports)."""
from __future__ import annotations

import uuid
from typing import AsyncContextManager, Protocol

from ..entities.scan import Scan, ScanStatus
from ..entities.scan_task import ScanTask, TaskStatus


class ScanRepository(Protocol):
    """Persistence port for Scan aggregates."""

    async def save(self, scan: Scan) -> None: ...

    async def get(self, scan_id: uuid.UUID, tenant_id: uuid.UUID) -> Scan | None: ...

    async def list_by_status(
        self,
        tenant_id: uuid.UUID,
        status: ScanStatus,
        limit: int = 100,
    ) -> list[Scan]: ...

    async def update_status(
        self,
        scan_id: uuid.UUID,
        status: ScanStatus,
        *,
        failure_reason: str | None = None,
    ) -> None: ...

    async def increment_task_counter(
        self,
        scan_id: uuid.UUID,
        *,
        completed_delta: int = 0,
        failed_delta: int = 0,
        retrying_delta: int = 0,
    ) -> None: ...


class ScanTaskRepository(Protocol):
    """Persistence port for ScanTask entities."""

    async def save(self, task: ScanTask) -> None: ...

    async def save_batch(self, tasks: list[ScanTask]) -> None: ...

    async def get(self, task_id: uuid.UUID) -> ScanTask | None: ...

    async def list_by_scan(
        self,
        scan_id: uuid.UUID,
        status: TaskStatus | None = None,
    ) -> list[ScanTask]: ...

    async def update(self, task: ScanTask) -> None: ...


class ScanQueue(Protocol):
    """Queue port — priority-ordered task dispatching."""

    async def enqueue(self, task: ScanTask, tenant_id: uuid.UUID) -> None: ...

    async def dequeue(
        self,
        worker_type: str,
        tenant_id: uuid.UUID | None = None,
        max_items: int = 1,
    ) -> list[ScanTask]: ...

    async def requeue_delayed(self, task: ScanTask, delay_seconds: float) -> None: ...

    async def move_to_dlq(self, task: ScanTask, reason: str) -> None: ...

    async def queue_depth(self, tenant_id: uuid.UUID | None = None) -> dict[str, int]: ...


class ScanEventPublisher(Protocol):
    """Domain event publishing port."""

    async def publish_scan_started(self, scan: Scan) -> None: ...

    async def publish_scan_completed(self, scan: Scan) -> None: ...

    async def publish_scan_failed(self, scan: Scan) -> None: ...
