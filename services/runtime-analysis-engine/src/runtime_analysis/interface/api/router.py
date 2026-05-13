from __future__ import annotations

from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from runtime_analysis.application.commands import AnalyzeURLCommand
from runtime_analysis.application.runtime_analysis_service import RuntimeAnalysisService
from runtime_analysis.domain.entities.analysis_session import AnalysisSession
from runtime_analysis.domain.ports import (
    AnalysisResultRepository,
    AnalysisSessionRepository,
)

router = APIRouter(prefix="/runtime-analysis", tags=["runtime-analysis"])


# ──────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ──────────────────────────────────────────────────────────────────────────────


class AnalysisRequest(BaseModel):
    tenant_id: str
    target_url: str
    correlation_id: str = ""
    max_spa_routes: int = Field(default=20, ge=1, le=100)
    timeout_seconds: int = Field(default=120, ge=10, le=600)


class SessionStatusResponse(BaseModel):
    session_id: str
    tenant_id: str
    target_url: str
    status: str
    result_id: str | None
    failure_reason: str | None
    duration_seconds: float | None
    created_at: str


class APIResponse(BaseModel):
    url: str
    method: str
    is_graphql: bool
    status_code: int | None
    params: list[str]


class WebSocketResponse(BaseModel):
    url: str
    protocols: list[str]
    message_count_sampled: int


class SPARouteResponse(BaseModel):
    path: str
    triggered_by: str
    lazy_chunks: list[str]


class AnalysisResultResponse(BaseModel):
    result_id: str
    session_id: str
    intercepted_apis_count: int
    websocket_endpoints_count: int
    spa_routes_count: int
    frameworks: list[dict]
    dom_snapshot: dict | None
    hydration_markers: dict


# ──────────────────────────────────────────────────────────────────────────────
# Dependency helpers (populated by main.py via request.app.state)
# ──────────────────────────────────────────────────────────────────────────────


def _get_service(request: "Request") -> RuntimeAnalysisService:  # noqa: F821
    return request.app.state.analysis_service


def _get_session_repo(request: "Request") -> AnalysisSessionRepository:  # noqa: F821
    return request.app.state.session_repo


def _get_result_repo(request: "Request") -> AnalysisResultRepository:  # noqa: F821
    return request.app.state.result_repo


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/sessions", status_code=status.HTTP_202_ACCEPTED)
async def create_session(
    body: AnalysisRequest,
    background: BackgroundTasks,
    request: "Request",  # noqa: F821
) -> dict:
    """Submit a new runtime analysis. Returns session_id immediately; analysis runs async."""
    from fastapi import Request as _Request  # avoid circular at module level

    service: RuntimeAnalysisService = request.app.state.analysis_service
    cmd = AnalyzeURLCommand(
        tenant_id=body.tenant_id,
        target_url=body.target_url,
        correlation_id=body.correlation_id,
        max_spa_routes=body.max_spa_routes,
        timeout_seconds=body.timeout_seconds,
    )
    background.add_task(service.analyze, cmd)
    return {"status": "accepted", "message": "Analysis scheduled"}


@router.get("/sessions/{session_id}", response_model=SessionStatusResponse)
async def get_session(session_id: str, request: "Request") -> SessionStatusResponse:  # noqa: F821
    repo: AnalysisSessionRepository = request.app.state.session_repo
    session = await repo.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_to_response(session)


@router.get("/sessions", response_model=list[SessionStatusResponse])
async def list_sessions(
    tenant_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    request: "Request" = None,  # type: ignore[assignment]
) -> list[SessionStatusResponse]:
    repo: AnalysisSessionRepository = request.app.state.session_repo
    sessions = await repo.list_by_tenant(tenant_id, limit=limit, offset=offset)  # type: ignore[arg-type]
    return [_session_to_response(s) for s in sessions]


@router.get("/sessions/{session_id}/result", response_model=AnalysisResultResponse)
async def get_result(session_id: str, request: "Request") -> AnalysisResultResponse:  # noqa: F821
    result_repo: AnalysisResultRepository = request.app.state.result_repo
    result = await result_repo.get_by_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not ready or session not found")
    return AnalysisResultResponse(
        result_id=result.result_id,
        session_id=result.session_id,
        intercepted_apis_count=len(result.intercepted_apis),
        websocket_endpoints_count=len(result.websocket_endpoints),
        spa_routes_count=len(result.spa_routes),
        frameworks=[fp.model_dump() for fp in result.framework_fingerprints],
        dom_snapshot=result.dom_snapshot.model_dump() if result.dom_snapshot else None,
        hydration_markers=result.hydration_markers,
    )


@router.get("/sessions/{session_id}/apis", response_model=list[APIResponse])
async def get_apis(
    session_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    request: "Request" = None,  # type: ignore[assignment]
) -> list[APIResponse]:
    result_repo: AnalysisResultRepository = request.app.state.result_repo
    result = await result_repo.get_by_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return [
        APIResponse(
            url=a.url,
            method=a.method,
            is_graphql=a.is_graphql,
            status_code=a.status_code,
            params=list(a.params),
        )
        for a in result.intercepted_apis[:limit]
    ]


@router.get("/sessions/{session_id}/websockets", response_model=list[WebSocketResponse])
async def get_websockets(session_id: str, request: "Request") -> list[WebSocketResponse]:  # noqa: F821
    result_repo: AnalysisResultRepository = request.app.state.result_repo
    result = await result_repo.get_by_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return [
        WebSocketResponse(
            url=w.url,
            protocols=list(w.protocols),
            message_count_sampled=len(w.message_samples),
        )
        for w in result.websocket_endpoints
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _session_to_response(session: AnalysisSession) -> SessionStatusResponse:
    return SessionStatusResponse(
        session_id=session.session_id,
        tenant_id=str(session.tenant_id),
        target_url=session.target_url,
        status=session.status.value,
        result_id=session.result_id,
        failure_reason=session.failure_reason,
        duration_seconds=session.duration_seconds,
        created_at=session.created_at.isoformat(),
    )
