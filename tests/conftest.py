"""Root conftest.py — shared fixtures for the entire test suite.

Provides:
  - Tenant/correlation UUID constants
  - In-memory fake implementations of all ports (ScanRepository, ScanQueue, etc.)
  - FastAPI TestClient factories for all services
  - Mock Kafka producer/consumer factories
  - anyio backend pinned to asyncio
"""
from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Constants ─────────────────────────────────────────────────────────────────

TENANT_A = uuid.UUID("10000000-0000-0000-0000-000000000001")
TENANT_B = uuid.UUID("20000000-0000-0000-0000-000000000002")
CORRELATION_ID = uuid.UUID("c0000000-0000-0000-0000-000000000001")


# ── In-memory fakes for scan-orchestrator ports ────────────────────────────────

class InMemoryScanRepository:
    def __init__(self) -> None:
        self._scans: dict[uuid.UUID, Any] = {}

    async def save(self, scan: Any) -> None:
        self._scans[scan.scan_id] = scan

    async def get(self, scan_id: uuid.UUID, tenant_id: uuid.UUID) -> Any | None:
        s = self._scans.get(scan_id)
        if s and s.tenant_id == tenant_id:
            return s
        return None

    async def list_by_status(self, tenant_id: uuid.UUID, status: Any, limit: int = 100) -> list:
        return [
            s for s in self._scans.values()
            if s.tenant_id == tenant_id and s.status == status
        ][:limit]

    async def update_status(self, scan_id: uuid.UUID, status: Any, *, failure_reason: str | None = None) -> None:
        if scan_id in self._scans:
            self._scans[scan_id].status = status
            if failure_reason:
                self._scans[scan_id].failure_reason = failure_reason

    async def increment_task_counter(
        self,
        scan_id: uuid.UUID,
        *,
        completed_delta: int = 0,
        failed_delta: int = 0,
        retrying_delta: int = 0,
    ) -> None:
        if scan_id in self._scans:
            s = self._scans[scan_id]
            s.tasks_completed += completed_delta
            s.tasks_failed += failed_delta
            s.tasks_retrying += retrying_delta


class InMemoryScanTaskRepository:
    def __init__(self) -> None:
        self._tasks: dict[uuid.UUID, Any] = {}

    async def save(self, task: Any) -> None:
        self._tasks[task.task_id] = task

    async def save_batch(self, tasks: list) -> None:
        for t in tasks:
            self._tasks[t.task_id] = t

    async def get(self, task_id: uuid.UUID) -> Any | None:
        return self._tasks.get(task_id)

    async def list_by_scan(self, scan_id: uuid.UUID, status: Any = None) -> list:
        results = [t for t in self._tasks.values() if t.scan_id == scan_id]
        if status is not None:
            results = [t for t in results if t.status == status]
        return results

    async def update(self, task: Any) -> None:
        self._tasks[task.task_id] = task


class InMemoryScanQueue:
    def __init__(self) -> None:
        self._queues: dict[str, list] = defaultdict(list)
        self._dlq: list = []

    async def enqueue(self, task: Any, tenant_id: uuid.UUID) -> None:
        self._queues[str(tenant_id)].append(task)

    async def dequeue(self, worker_type: str, tenant_id: uuid.UUID | None = None, max_items: int = 1) -> list:
        key = str(tenant_id) if tenant_id else next(iter(self._queues), None)
        if key and self._queues[key]:
            items = self._queues[key][:max_items]
            self._queues[key] = self._queues[key][max_items:]
            return items
        return []

    async def requeue_delayed(self, task: Any, delay_seconds: float) -> None:
        key = str(task.tenant_id)
        self._queues[key].append(task)

    async def move_to_dlq(self, task: Any, reason: str) -> None:
        self._dlq.append((task, reason))

    async def queue_depth(self, tenant_id: uuid.UUID | None = None) -> dict[str, int]:
        if tenant_id:
            return {"total": len(self._queues.get(str(tenant_id), []))}
        return {"total": sum(len(q) for q in self._queues.values())}

    async def start_delayed_mover(self) -> None:
        pass


class InMemoryEventPublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, Any]] = []

    async def publish_scan_started(self, scan: Any) -> None:
        self.events.append(("scan.started", scan))

    async def publish_scan_completed(self, scan: Any) -> None:
        self.events.append(("scan.completed", scan))

    async def publish_scan_failed(self, scan: Any) -> None:
        self.events.append(("scan.failed", scan))


# ── Pytest fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def tenant_id() -> uuid.UUID:
    return TENANT_A


@pytest.fixture
def correlation_id() -> uuid.UUID:
    return CORRELATION_ID


@pytest.fixture
def scan_repo() -> InMemoryScanRepository:
    return InMemoryScanRepository()


@pytest.fixture
def task_repo() -> InMemoryScanTaskRepository:
    return InMemoryScanTaskRepository()


@pytest.fixture
def scan_queue() -> InMemoryScanQueue:
    return InMemoryScanQueue()


@pytest.fixture
def event_publisher() -> InMemoryEventPublisher:
    return InMemoryEventPublisher()


@pytest.fixture
def mock_kafka_producer() -> MagicMock:
    producer = MagicMock()
    producer.produce_envelope = AsyncMock()
    producer.start = AsyncMock()
    producer.stop = AsyncMock()
    return producer


@pytest.fixture
def mock_redis() -> MagicMock:
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.setex = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.exists = AsyncMock(return_value=0)
    redis.ping = AsyncMock(return_value=True)
    redis.zadd = AsyncMock()
    redis.zrange = AsyncMock(return_value=[])
    redis.zrangebyscore = AsyncMock(return_value=[])
    redis.aclose = AsyncMock()
    return redis


@pytest.fixture
def now() -> datetime:
    return datetime.now(tz=timezone.utc)
