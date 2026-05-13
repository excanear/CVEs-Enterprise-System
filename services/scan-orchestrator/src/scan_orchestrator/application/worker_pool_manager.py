"""Worker pool manager — async semaphore-bounded execution pools.

Each scan type has its own semaphore pool to prevent a single scan type
from starving others. Tenant-level semaphores enforce fairness across tenants.

Pools:
  global   — overall cap on concurrent scan operations
  per-type — cap per ScanType (NETWORK_DISCOVERY, PORT_SCAN, etc.)
  per-tenant — cap on concurrent tasks per tenant (fairness)
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator, Final

logger = logging.getLogger(__name__)

# Defaults — overridden via WorkerPoolConfig
_GLOBAL_LIMIT: Final[int] = 200
_PER_TYPE_LIMIT: Final[int] = 50
_PER_TENANT_LIMIT: Final[int] = 30
_ACQUIRE_TIMEOUT: Final[float] = 30.0   # seconds to wait for a slot


@dataclass
class PoolStats:
    name: str
    capacity: int
    in_use: int

    @property
    def available(self) -> int:
        return max(0, self.capacity - self.in_use)

    @property
    def utilization_pct(self) -> float:
        if not self.capacity:
            return 100.0
        return round(self.in_use / self.capacity * 100, 2)


class _BoundedSemaphore:
    """asyncio.Semaphore with usage tracking."""

    def __init__(self, capacity: int, name: str) -> None:
        self._capacity = capacity
        self._name = name
        self._sem = asyncio.Semaphore(capacity)
        self._in_use = 0

    @contextlib.asynccontextmanager
    async def acquire(self, timeout: float = _ACQUIRE_TIMEOUT) -> AsyncIterator[None]:
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"Worker pool '{self._name}' saturated — timed out after {timeout}s"
            )
        self._in_use += 1
        try:
            yield
        finally:
            self._in_use -= 1
            self._sem.release()

    def stats(self) -> PoolStats:
        return PoolStats(
            name=self._name,
            capacity=self._capacity,
            in_use=self._in_use,
        )


class WorkerPoolManager:
    """Manages hierarchical semaphore pools for scan task execution.

    Callers acquire slots via the context manager — guarantees release on exit.

    Usage::

        async with pool_manager.acquire(task_type="PORT_SCAN", tenant_id=tid):
            await execute_task(task)
    """

    def __init__(
        self,
        *,
        global_limit: int = _GLOBAL_LIMIT,
        per_type_limits: dict[str, int] | None = None,
        per_tenant_limit: int = _PER_TENANT_LIMIT,
    ) -> None:
        self._global = _BoundedSemaphore(global_limit, "global")
        self._per_type: dict[str, _BoundedSemaphore] = {}
        self._per_tenant: dict[uuid.UUID, _BoundedSemaphore] = {}
        self._per_type_default = _PER_TYPE_LIMIT
        self._per_tenant_limit = per_tenant_limit
        self._lock = asyncio.Lock()

        if per_type_limits:
            for name, cap in per_type_limits.items():
                self._per_type[name] = _BoundedSemaphore(cap, f"type:{name}")

    @contextlib.asynccontextmanager
    async def acquire(
        self,
        task_type: str,
        tenant_id: uuid.UUID,
        *,
        timeout: float = _ACQUIRE_TIMEOUT,
    ) -> AsyncIterator[None]:
        """Acquire slots from global + per-type + per-tenant pools simultaneously."""
        type_pool = await self._get_or_create_type_pool(task_type)
        tenant_pool = await self._get_or_create_tenant_pool(tenant_id)

        async with self._global.acquire(timeout=timeout):
            async with type_pool.acquire(timeout=timeout):
                async with tenant_pool.acquire(timeout=timeout):
                    yield

    def get_all_stats(self) -> dict[str, PoolStats]:
        stats: dict[str, PoolStats] = {"global": self._global.stats()}
        for k, v in self._per_type.items():
            stats[f"type:{k}"] = v.stats()
        for k, v in self._per_tenant.items():
            stats[f"tenant:{k}"] = v.stats()
        return stats

    async def _get_or_create_type_pool(self, task_type: str) -> _BoundedSemaphore:
        async with self._lock:
            if task_type not in self._per_type:
                self._per_type[task_type] = _BoundedSemaphore(
                    self._per_type_default, f"type:{task_type}"
                )
            return self._per_type[task_type]

    async def _get_or_create_tenant_pool(self, tenant_id: uuid.UUID) -> _BoundedSemaphore:
        async with self._lock:
            if tenant_id not in self._per_tenant:
                self._per_tenant[tenant_id] = _BoundedSemaphore(
                    self._per_tenant_limit, f"tenant:{tenant_id}"
                )
            return self._per_tenant[tenant_id]
