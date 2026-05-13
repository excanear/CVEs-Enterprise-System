"""FastAPI router for the Discovery Engine.

Endpoints:
  POST   /discovery/jobs                    — start a discovery job (async)
  GET    /discovery/jobs                    — list tenant's jobs
  GET    /discovery/jobs/{job_id}           — job status + stats
  GET    /discovery/jobs/{job_id}/assets    — assets found by a job
  GET    /discovery/assets                  — list assets by type
  GET    /discovery/assets/{asset_id}       — single asset detail
  PATCH  /discovery/assets/{asset_id}/status — update asset status
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ...application.commands import RunDiscoveryCommand
from ...application.discovery_service import DiscoveryService
from ...domain.entities.discovered_asset import AssetStatus, AssetType
from ...domain.entities.discovery_job import DiscoverySourceConfig

router = APIRouter(prefix="/api/v1", tags=["discovery-engine"])


# ── Request / Response schemas ────────────────────────────────────────────────

class RunDiscoveryRequest(BaseModel):
    target_domain: str = Field(min_length=1, max_length=253)
    scope_domains: list[str] = Field(default_factory=list, max_length=50)
    sources: list[DiscoverySourceConfig] = Field(default_factory=list)
    max_depth: int = Field(default=3, ge=1, le=5)
    max_pages: int = Field(default=200, ge=1, le=2000)
    max_rps: float = Field(default=5.0, ge=0.1, le=50.0)
    allow_internal: bool = False


class JobResponse(BaseModel):
    job_id: uuid.UUID
    target_domain: str
    status: str
    assets_found: int
    endpoints_found: int
    duration_seconds: float | None
    sources: list[str]


class AssetResponse(BaseModel):
    asset_id: uuid.UUID
    asset_type: str
    value: str
    source: str
    status: str
    confidence: float
    first_seen_at: str
    last_seen_at: str
    tags: list[str]


class UpdateStatusRequest(BaseModel):
    status: AssetStatus


# ── Dependencies ──────────────────────────────────────────────────────────────

def _get_svc(request: Request) -> DiscoveryService:
    return request.app.state.discovery_svc


def _tenant_id(request: Request) -> uuid.UUID:
    tid = getattr(request.state, "tenant_id", None)
    if not tid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing tenant context.")
    return tid


def _initiated_by(request: Request) -> str:
    return getattr(request.state, "jwt_claims", {}).get("sub", "unknown")


# ── Job endpoints ─────────────────────────────────────────────────────────────

@router.post("/discovery/jobs", status_code=status.HTTP_202_ACCEPTED)
async def start_discovery(
    body: RunDiscoveryRequest,
    background_tasks: BackgroundTasks,
    tenant_id: uuid.UUID = Depends(_tenant_id),
    initiated_by: str = Depends(_initiated_by),
    svc: DiscoveryService = Depends(_get_svc),
) -> dict[str, Any]:
    from cves_db.types import uuid7

    cmd = RunDiscoveryCommand(
        tenant_id=tenant_id,
        target_domain=body.target_domain,
        initiated_by=initiated_by,
        correlation_id=uuid7(),
        scope_domains=body.scope_domains or [body.target_domain],
        sources=list(body.sources),
        max_depth=body.max_depth,
        max_pages=body.max_pages,
        max_rps=body.max_rps,
        allow_internal=body.allow_internal,
    )
    # Fire-and-forget via BackgroundTasks so the response is immediate
    background_tasks.add_task(svc.run_discovery, cmd)
    return {
        "status": "accepted",
        "correlation_id": str(cmd.correlation_id),
        "target_domain": cmd.target_domain,
    }


@router.get("/discovery/jobs")
async def list_jobs(
    limit: int = Query(default=20, le=100),
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> list[JobResponse]:
    jobs = await svc._job_repo.list_by_tenant(tenant_id, limit=limit)
    return [_job_response(j) for j in jobs]


@router.get("/discovery/jobs/{job_id}")
async def get_job(
    job_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> JobResponse:
    job = await svc._job_repo.get(job_id)
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    return _job_response(job)


@router.get("/discovery/jobs/{job_id}/assets")
async def list_job_assets(
    job_id: uuid.UUID,
    asset_type: AssetType | None = Query(default=None),
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> list[AssetResponse]:
    job = await svc._job_repo.get(job_id)
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    assets = await svc._asset_repo.list_by_job(job_id)
    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]
    return [_asset_response(a) for a in assets]


# ── Asset endpoints ───────────────────────────────────────────────────────────

@router.get("/discovery/assets")
async def list_assets(
    asset_type: AssetType = Query(...),
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> list[AssetResponse]:
    assets = await svc._asset_repo.list_by_type(tenant_id, asset_type)
    return [_asset_response(a) for a in assets]


@router.get("/discovery/assets/{asset_id}")
async def get_asset(
    asset_id: uuid.UUID,
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> AssetResponse:
    asset = await svc._asset_repo.get(asset_id)
    if not asset or asset.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return _asset_response(asset)


@router.patch("/discovery/assets/{asset_id}/status", status_code=status.HTTP_204_NO_CONTENT)
async def update_asset_status(
    asset_id: uuid.UUID,
    body: UpdateStatusRequest,
    tenant_id: uuid.UUID = Depends(_tenant_id),
    svc: DiscoveryService = Depends(_get_svc),
) -> None:
    asset = await svc._asset_repo.get(asset_id)
    if not asset or asset.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Asset not found.")
    await svc._asset_repo.update_status(asset_id, body.status)


# ── Response builders ─────────────────────────────────────────────────────────

def _job_response(job) -> JobResponse:
    return JobResponse(
        job_id=job.job_id,
        target_domain=job.target_domain,
        status=job.status,
        assets_found=job.assets_found,
        endpoints_found=job.endpoints_found,
        duration_seconds=job.duration_seconds,
        sources=[s.value for s in job.sources],
    )


def _asset_response(asset) -> AssetResponse:
    return AssetResponse(
        asset_id=asset.asset_id,
        asset_type=asset.asset_type,
        value=asset.value,
        source=asset.source,
        status=asset.status,
        confidence=asset.confidence,
        first_seen_at=asset.first_seen_at.isoformat(),
        last_seen_at=asset.last_seen_at.isoformat(),
        tags=asset.tags,
    )
