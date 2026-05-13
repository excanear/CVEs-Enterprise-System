"""SQLAlchemy async repository implementations for Scan and ScanTask."""
from __future__ import annotations

import uuid
from datetime import timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ...domain.entities.scan import Scan, ScanPriority, ScanStatus, ScanType
from ...domain.entities.scan_task import ScanTask, TaskStatus, TaskType
from .models import ScanModel, ScanTaskModel


# ── Mapper helpers ────────────────────────────────────────────────────────────

def _scan_to_domain(row: ScanModel) -> Scan:
    from datetime import datetime, timezone

    def _dt(v):
        if v is None:
            return None
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

    return Scan(
        scan_id=row.scan_id,
        tenant_id=row.tenant_id,
        scan_type=ScanType(row.scan_type),
        priority=ScanPriority(row.priority),
        initiated_by=row.initiated_by,
        config_snapshot=row.config_snapshot,
        targets=list(row.targets),
        correlation_id=row.correlation_id,
        status=ScanStatus(row.status),
        scheduled_at=_dt(row.scheduled_at),
        started_at=_dt(row.started_at),
        completed_at=_dt(row.completed_at),
        failure_reason=row.failure_reason,
        tasks_total=row.tasks_total,
        tasks_completed=row.tasks_completed,
        tasks_failed=row.tasks_failed,
        tasks_retrying=row.tasks_retrying,
        assigned_worker_ids=list(row.assigned_worker_ids or []),
    )


def _task_to_domain(row: ScanTaskModel) -> ScanTask:
    from datetime import datetime, timezone

    def _dt(v):
        if v is None:
            return None
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v

    return ScanTask(
        task_id=row.task_id,
        scan_id=row.scan_id,
        tenant_id=row.tenant_id,
        target=row.target,
        task_type=TaskType(row.task_type),
        priority_score=row.priority_score,
        config=dict(row.config),
        status=TaskStatus(row.status),
        attempt_count=row.attempt_count,
        max_attempts=row.max_attempts,
        assigned_worker_id=row.assigned_worker_id,
        dispatched_at=_dt(row.dispatched_at),
        started_at=_dt(row.started_at),
        completed_at=_dt(row.completed_at),
        next_retry_at=_dt(row.next_retry_at),
        result=dict(row.result),
        error_message=row.error_message,
        last_error_code=row.last_error_code,
    )


# ── Scan Repository ───────────────────────────────────────────────────────────

class PostgresScanRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, scan: Scan) -> None:
        existing = await self._session.get(ScanModel, scan.scan_id)
        if existing:
            existing.status = scan.status
            existing.tasks_total = scan.tasks_total
            existing.tasks_completed = scan.tasks_completed
            existing.tasks_failed = scan.tasks_failed
            existing.tasks_retrying = scan.tasks_retrying
            existing.scheduled_at = scan.scheduled_at
            existing.started_at = scan.started_at
            existing.completed_at = scan.completed_at
            existing.failure_reason = scan.failure_reason
            existing.assigned_worker_ids = [str(w) for w in scan.assigned_worker_ids]
        else:
            row = ScanModel(
                scan_id=scan.scan_id,
                tenant_id=scan.tenant_id,
                scan_type=scan.scan_type,
                status=scan.status,
                priority=scan.priority,
                initiated_by=scan.initiated_by,
                correlation_id=scan.correlation_id,
                targets=scan.targets,
                config_snapshot=scan.config_snapshot,
                tasks_total=scan.tasks_total,
                tasks_completed=scan.tasks_completed,
                tasks_failed=scan.tasks_failed,
                tasks_retrying=scan.tasks_retrying,
                scheduled_at=scan.scheduled_at,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                failure_reason=scan.failure_reason,
                assigned_worker_ids=[str(w) for w in scan.assigned_worker_ids],
            )
            self._session.add(row)
        await self._session.flush()

    async def get(self, scan_id: uuid.UUID, tenant_id: uuid.UUID) -> Scan | None:
        stmt = (
            select(ScanModel)
            .where(ScanModel.scan_id == scan_id, ScanModel.tenant_id == tenant_id)
        )
        row = (await self._session.execute(stmt)).scalar_one_or_none()
        return _scan_to_domain(row) if row else None

    async def list_by_status(
        self,
        tenant_id: uuid.UUID,
        status: ScanStatus,
        limit: int = 100,
    ) -> list[Scan]:
        stmt = (
            select(ScanModel)
            .where(ScanModel.tenant_id == tenant_id, ScanModel.status == status)
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_scan_to_domain(r) for r in rows]

    async def update_status(
        self,
        scan_id: uuid.UUID,
        status: ScanStatus,
        *,
        failure_reason: str | None = None,
    ) -> None:
        values: dict = {"status": status}
        if failure_reason:
            values["failure_reason"] = failure_reason
        await self._session.execute(
            update(ScanModel).where(ScanModel.scan_id == scan_id).values(**values)
        )

    async def increment_task_counter(
        self,
        scan_id: uuid.UUID,
        *,
        completed_delta: int = 0,
        failed_delta: int = 0,
        retrying_delta: int = 0,
    ) -> None:
        from sqlalchemy import text

        await self._session.execute(
            text(
                "UPDATE scan_orchestrator.scans SET "
                "tasks_completed = tasks_completed + :c, "
                "tasks_failed = tasks_failed + :f, "
                "tasks_retrying = tasks_retrying + :r "
                "WHERE scan_id = :sid"
            ),
            {"c": completed_delta, "f": failed_delta, "r": retrying_delta, "sid": scan_id},
        )


# ── ScanTask Repository ───────────────────────────────────────────────────────

class PostgresScanTaskRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, task: ScanTask) -> None:
        row = ScanTaskModel(
            task_id=task.task_id,
            scan_id=task.scan_id,
            tenant_id=task.tenant_id,
            target=task.target,
            task_type=task.task_type,
            status=task.status,
            priority_score=task.priority_score,
            config=task.config,
            attempt_count=task.attempt_count,
            max_attempts=task.max_attempts,
        )
        self._session.add(row)
        await self._session.flush()

    async def save_batch(self, tasks: list[ScanTask]) -> None:
        for task in tasks:
            await self.save(task)

    async def get(self, task_id: uuid.UUID) -> ScanTask | None:
        row = await self._session.get(ScanTaskModel, task_id)
        return _task_to_domain(row) if row else None

    async def list_by_scan(
        self,
        scan_id: uuid.UUID,
        status: TaskStatus | None = None,
    ) -> list[ScanTask]:
        stmt = select(ScanTaskModel).where(ScanTaskModel.scan_id == scan_id)
        if status:
            stmt = stmt.where(ScanTaskModel.status == status)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [_task_to_domain(r) for r in rows]

    async def update(self, task: ScanTask) -> None:
        row = await self._session.get(ScanTaskModel, task.task_id)
        if not row:
            return
        row.status = task.status
        row.attempt_count = task.attempt_count
        row.assigned_worker_id = task.assigned_worker_id
        row.dispatched_at = task.dispatched_at
        row.started_at = task.started_at
        row.completed_at = task.completed_at
        row.next_retry_at = task.next_retry_at
        row.result = task.result
        row.error_message = task.error_message
        row.last_error_code = task.last_error_code
        await self._session.flush()
