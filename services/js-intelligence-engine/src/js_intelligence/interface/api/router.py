from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from js_intelligence.application.commands import AnalyzeJSCommand
from js_intelligence.application.js_intelligence_service import JSIntelligenceService
from js_intelligence.domain.ports import (
    JSAnalysisJobRepository,
    JSIntelligenceResultRepository,
)

router = APIRouter(prefix="/js-intelligence", tags=["js-intelligence"])


# ──────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ──────────────────────────────────────────────────────────────────────────────


class AnalyzeJSRequest(BaseModel):
    tenant_id: str
    target_url: str
    correlation_id: str = ""
    max_js_files: int = Field(default=50, ge=1, le=200)
    fetch_source_maps: bool = True
    timeout_seconds: int = Field(default=300, ge=30, le=1800)


class JobStatusResponse(BaseModel):
    job_id: str
    tenant_id: str
    target_url: str
    status: str
    result_id: str | None
    failure_reason: str | None
    duration_seconds: float | None
    stats: dict[str, Any]
    created_at: str


class BundleResponse(BaseModel):
    url: str
    content_hash: str
    size_bytes: int
    is_minified: bool
    bundler: str
    chunk_id: str | None
    source_map_url: str | None


class RouteResponse(BaseModel):
    path: str
    router_type: str
    component_hint: str | None
    confidence: float
    discovered_in_chunk: str
    lazy_chunks: list[str]


class GraphResponse(BaseModel):
    node_count: int
    edge_count: int
    has_cycles: bool
    cycle_node_count: int
    entry_points: list[str]
    nodes: list[dict[str, Any]]
    edges: list[list[str]]


class ResultSummaryResponse(BaseModel):
    result_id: str
    job_id: str
    bundle_count: int
    source_map_entry_count: int
    route_count: int
    bundler: str
    version_hint: str | None
    chunk_strategy: str
    has_source_maps: bool
    dependency_graph: dict[str, Any]


# ──────────────────────────────────────────────────────────────────────────────
# DI helpers (populated by main.py via app.state)
# ──────────────────────────────────────────────────────────────────────────────


def _get_service(request: Request) -> JSIntelligenceService:
    return request.app.state.js_intelligence_service


def _get_job_repo(request: Request) -> JSAnalysisJobRepository:
    return request.app.state.job_repo


def _get_result_repo(request: Request) -> JSIntelligenceResultRepository:
    return request.app.state.result_repo


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
async def submit_job(
    body: AnalyzeJSRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict[str, str]:
    svc = _get_service(request)
    cmd = AnalyzeJSCommand(
        tenant_id=body.tenant_id,
        target_url=body.target_url,
        correlation_id=body.correlation_id,
        max_js_files=body.max_js_files,
        fetch_source_maps=body.fetch_source_maps,
        timeout_seconds=body.timeout_seconds,
    )
    background_tasks.add_task(svc.analyze, cmd)
    return {"status": "accepted", "message": "Job submitted. Poll GET /jobs to track status."}


@router.post("/jobs/sync", status_code=status.HTTP_200_OK, include_in_schema=False)
async def submit_job_sync(
    body: AnalyzeJSRequest,
    request: Request,
) -> dict[str, str]:
    """Synchronous variant for internal use / testing."""
    svc = _get_service(request)
    cmd = AnalyzeJSCommand(
        tenant_id=body.tenant_id,
        target_url=body.target_url,
        correlation_id=body.correlation_id,
        max_js_files=body.max_js_files,
        fetch_source_maps=body.fetch_source_maps,
        timeout_seconds=body.timeout_seconds,
    )
    job_id = await svc.analyze(cmd)
    return {"job_id": job_id}


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job(job_id: str, request: Request) -> JobStatusResponse:
    repo = _get_job_repo(request)
    job = await repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.job_id,
        tenant_id=str(job.tenant_id),
        target_url=job.target_url,
        status=job.status.value,
        result_id=job.result_id,
        failure_reason=job.failure_reason,
        duration_seconds=job.duration_seconds,
        stats=job.stats,
        created_at=job.created_at.isoformat(),
    )


@router.get("/jobs", response_model=list[JobStatusResponse])
async def list_jobs(
    request: Request,
    tenant_id: str = Query(...),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[JobStatusResponse]:
    from cves_db.types import TenantId

    repo = _get_job_repo(request)
    jobs = await repo.list_by_tenant(TenantId(tenant_id), limit=limit, offset=offset)
    return [
        JobStatusResponse(
            job_id=j.job_id,
            tenant_id=str(j.tenant_id),
            target_url=j.target_url,
            status=j.status.value,
            result_id=j.result_id,
            failure_reason=j.failure_reason,
            duration_seconds=j.duration_seconds,
            stats=j.stats,
            created_at=j.created_at.isoformat(),
        )
        for j in jobs
    ]


@router.get("/jobs/{job_id}/result", response_model=ResultSummaryResponse)
async def get_result(job_id: str, request: Request) -> ResultSummaryResponse:
    result_repo = _get_result_repo(request)
    result = await result_repo.get_by_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return ResultSummaryResponse(
        result_id=result.result_id,
        job_id=result.job_id,
        bundle_count=len(result.bundles),
        source_map_entry_count=len(result.source_map_entries),
        route_count=len(result.hidden_routes),
        bundler=result.bundler_signature.bundler,
        version_hint=result.bundler_signature.version_hint,
        chunk_strategy=result.bundler_signature.chunk_strategy,
        has_source_maps=result.bundler_signature.has_source_maps,
        dependency_graph={
            "node_count": result.dependency_graph.node_count,
            "edge_count": result.dependency_graph.edge_count,
            "has_cycles": result.dependency_graph.has_cycles,
        },
    )


@router.get("/jobs/{job_id}/routes", response_model=list[RouteResponse])
async def get_routes(
    job_id: str,
    request: Request,
    router_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[RouteResponse]:
    result_repo = _get_result_repo(request)
    result = await result_repo.get_by_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")

    routes = list(result.hidden_routes)
    if router_type:
        routes = [r for r in routes if r.router_type == router_type.upper()]

    paginated = routes[offset : offset + limit]
    return [
        RouteResponse(
            path=r.path,
            router_type=r.router_type,
            component_hint=r.component_hint,
            confidence=r.confidence,
            discovered_in_chunk=r.discovered_in_chunk,
            lazy_chunks=list(r.lazy_chunks),
        )
        for r in paginated
    ]


@router.get("/jobs/{job_id}/bundles", response_model=list[BundleResponse])
async def get_bundles(job_id: str, request: Request) -> list[BundleResponse]:
    result_repo = _get_result_repo(request)
    result = await result_repo.get_by_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")
    return [
        BundleResponse(
            url=b.url,
            content_hash=b.content_hash,
            size_bytes=b.size_bytes,
            is_minified=b.is_minified,
            bundler=b.bundler,
            chunk_id=b.chunk_id,
            source_map_url=b.source_map_url,
        )
        for b in result.bundles
    ]


@router.get("/jobs/{job_id}/graph", response_model=GraphResponse)
async def get_graph(job_id: str, request: Request) -> GraphResponse:
    result_repo = _get_result_repo(request)
    result = await result_repo.get_by_job(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Result not found")

    graph = result.dependency_graph
    return GraphResponse(
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        has_cycles=graph.has_cycles,
        cycle_node_count=len(graph.cycle_node_ids),
        entry_points=graph.entry_points,
        nodes=[n.model_dump() for n in graph.nodes],
        edges=[list(e) for e in graph.edges],
    )
