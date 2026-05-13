"""FastAPI router for scan orchestration.

Endpoints:
  POST   /scans                     — submit a scan
  GET    /scans/{scan_id}           — get scan status + progress
  DELETE /scans/{scan_id}           — cancel scan
  POST   /scans/{scan_id}/retry     — retry failed tasks
  GET    /scans                     — list scans by status
  GET    /workers/pools             — worker pool utilization
  GET    /workers/heartbeats        — live worker heartbeats
  GET    /queue/depth               — queue depth per tenant
  GET    /scheduler/jobs            — list scheduled jobs
  POST   /scheduler/jobs            — register recurring scan
  DELETE /scheduler/jobs/{job_id}   — unregister job
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ...application.commands import CancelScanCommand, RetryFailedTasksCommand, SubmitScanCommand
from ...application.scan_orchestration_service import ScanOrchestrationService
from ...application.worker_pool_manager import WorkerPoolManager
from ...domain.entities.scan import ScanPriority, ScanStatus, ScanType
from ...domain.value_objects.scan_config import ScanConfig
from ...infrastructure.queue.redis_scan_queue import RedisScanQueue
from ...infrastructure.scheduler.distributed_scheduler import DistributedScheduler, ScheduledJob

router = APIRouter(prefix="/api/v1", tags=["scan-orchestrator"])


# ── Request/Response schemas ──────────────────────────────────────────────────

class SubmitScanRequest(BaseModel):
    scan_type: ScanType
    targets: list[str] = Field(min_length=1, max_length=5000)
    priority: ScanPriority = ScanPriority.NORMAL
    config: dict = Field(default_factory=dict)
    schedule_cron: str | None = None


class ScanStatusResponse(BaseModel):
    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    scan_type: str
    status: str
    priority: str
    tasks_total: int
    tasks_completed: int
    tasks_failed: int
    tasks_retrying: int
    progress_pct: float
    initiated_by: str


class RegisterJobRequest(BaseModel):
    name: str
    cron_expression: str
    scan_type: ScanType
    targets: list[str]
    priority: ScanPriority = ScanPriority.NORMAL
    config: dict = Field(default_factory=dict)


# ── Dependencies ──────────────────────────────────────────────────────────────

def _get_orchestration_svc(request: Request) -> ScanOrchestrationService:
    return request.app.state.orchestration_svc


def _get_worker_pool(request: Request) -> WorkerPoolManager:
    return request.app.state.worker_pool


def _get_scan_queue(request: Request) -> RedisScanQueue:
    return request.app.state.scan_queue


def _get_scheduler(request: Request) -> DistributedScheduler:
    return request.app.state.scheduler


def _get_tenant_id(request: Request) -> uuid.UUID:
    """Extract authenticated tenant_id from request state (set by JWT middleware)."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant context.")
    return tenant_id


def _get_initiated_by(request: Request) -> str:
    claims = getattr(request.state, "jwt_claims", {})
    return claims.get("sub", "unknown")


# ── Scan endpoints ────────────────────────────────────────────────────────────

@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
async def submit_scan(
    body: SubmitScanRequest,
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    initiated_by: str = Depends(_get_initiated_by),
    svc: ScanOrchestrationService = Depends(_get_orchestration_svc),
) -> dict[str, Any]:
    from cves_db.types import uuid7

    cmd = SubmitScanCommand(
        tenant_id=tenant_id,
        scan_type=body.scan_type,
        targets=body.targets,
        priority=body.priority,
        initiated_by=initiated_by,
        correlation_id=uuid7(),
        config=ScanConfig.from_dict(body.config),
        schedule_cron=body.schedule_cron,
    )
    scan_id = await svc.submit_scan(cmd)
    return {"scan_id": str(scan_id), "status": "SCHEDULED"}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    svc: ScanOrchestrationService = Depends(_get_orchestration_svc),
) -> ScanStatusResponse:
    scan = await svc._scan_repo.get(scan_id, tenant_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanStatusResponse(
        scan_id=scan.scan_id,
        tenant_id=scan.tenant_id,
        scan_type=scan.scan_type,
        status=scan.status,
        priority=scan.priority,
        tasks_total=scan.tasks_total,
        tasks_completed=scan.tasks_completed,
        tasks_failed=scan.tasks_failed,
        tasks_retrying=scan.tasks_retrying,
        progress_pct=scan.progress_pct,
        initiated_by=scan.initiated_by,
    )


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    initiated_by: str = Depends(_get_initiated_by),
    svc: ScanOrchestrationService = Depends(_get_orchestration_svc),
) -> None:
    try:
        await svc.cancel_scan(CancelScanCommand(
            tenant_id=tenant_id,
            scan_id=scan_id,
            cancelled_by=initiated_by,
        ))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/scans/{scan_id}/retry", status_code=status.HTTP_200_OK)
async def retry_failed_tasks(
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    initiated_by: str = Depends(_get_initiated_by),
    svc: ScanOrchestrationService = Depends(_get_orchestration_svc),
) -> dict[str, Any]:
    try:
        count = await svc.retry_failed_tasks(RetryFailedTasksCommand(
            tenant_id=tenant_id,
            scan_id=scan_id,
            requested_by=initiated_by,
        ))
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"retried_task_count": count}


@router.get("/scans")
async def list_scans(
    scan_status: ScanStatus = Query(default=ScanStatus.RUNNING),
    limit: int = Query(default=50, le=200),
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    svc: ScanOrchestrationService = Depends(_get_orchestration_svc),
) -> list[ScanStatusResponse]:
    scans = await svc._scan_repo.list_by_status(tenant_id, scan_status, limit=limit)
    return [
        ScanStatusResponse(
            scan_id=s.scan_id,
            tenant_id=s.tenant_id,
            scan_type=s.scan_type,
            status=s.status,
            priority=s.priority,
            tasks_total=s.tasks_total,
            tasks_completed=s.tasks_completed,
            tasks_failed=s.tasks_failed,
            tasks_retrying=s.tasks_retrying,
            progress_pct=s.progress_pct,
            initiated_by=s.initiated_by,
        )
        for s in scans
    ]


# ── Worker pool endpoints ─────────────────────────────────────────────────────

@router.get("/workers/pools")
async def get_pool_stats(
    pool: WorkerPoolManager = Depends(_get_worker_pool),
) -> dict[str, Any]:
    stats = pool.get_all_stats()
    return {
        name: {
            "capacity": s.capacity,
            "in_use": s.in_use,
            "available": s.available,
            "utilization_pct": s.utilization_pct,
        }
        for name, s in stats.items()
    }


# ── Queue endpoints ───────────────────────────────────────────────────────────

@router.get("/queue/depth")
async def get_queue_depth(
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    queue: RedisScanQueue = Depends(_get_scan_queue),
) -> dict[str, int]:
    return await queue.queue_depth(tenant_id)


# ── Scheduler endpoints ───────────────────────────────────────────────────────

@router.get("/scheduler/jobs")
async def list_jobs(
    scheduler: DistributedScheduler = Depends(_get_scheduler),
) -> list[dict]:
    return scheduler.list_jobs()


@router.post("/scheduler/jobs", status_code=status.HTTP_201_CREATED)
async def register_job(
    body: RegisterJobRequest,
    tenant_id: uuid.UUID = Depends(_get_tenant_id),
    scheduler: DistributedScheduler = Depends(_get_scheduler),
) -> dict[str, str]:
    from cves_db.types import uuid7

    job = ScheduledJob(
        job_id=str(uuid7()),
        name=body.name,
        cron_expression=body.cron_expression,
        payload={
            "tenant_id": str(tenant_id),
            "scan_type": body.scan_type,
            "targets": body.targets,
            "priority": body.priority,
            "config": body.config,
        },
    )
    await scheduler.register_job(job)
    return {"job_id": job.job_id}


@router.delete("/scheduler/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unregister_job(
    job_id: str,
    scheduler: DistributedScheduler = Depends(_get_scheduler),
) -> None:
    await scheduler.unregister_job(job_id)
