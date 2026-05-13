"""FastAPI router for Exposure Validation Engine.

Endpoints:
  POST   /exposure-validation/jobs          — submit async validation job (202)
  POST   /exposure-validation/jobs/sync     — submit & wait for result (200, hidden)
  GET    /exposure-validation/jobs/{job_id} — get job status
  GET    /exposure-validation/jobs          — list jobs by tenant
  GET    /exposure-validation/jobs/{job_id}/result   — full validation result
  GET    /exposure-validation/jobs/{job_id}/evidence — per-stage breakdown
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from cves_event_schemas.eve.eve_events import ExposureType

from exposure_validation.application.commands import ValidateExposureCommand
from exposure_validation.application.exposure_validation_service import ExposureValidationService
from exposure_validation.domain.ports import ValidationJobRepository, ValidationResultRepository

router = APIRouter(prefix="/exposure-validation", tags=["exposure-validation"])


# ── Request / Response schemas ────────────────────────────────────────────────

class ValidateRequest(BaseModel):
    tenant_id: str
    target_url: str
    exposure_type: ExposureType
    signal_source: str = "manual"
    endpoint_path: str = ""
    method: str = "GET"
    param_names: list[str] = Field(default_factory=list)
    confidence_hint: float = Field(default=0.5, ge=0.0, le=1.0)
    correlation_id: str = ""
    timeout_seconds: int = Field(default=120, ge=10, le=600)


class JobStatusResponse(BaseModel):
    job_id: str
    tenant_id: str
    target_url: str
    exposure_type: str
    status: str
    result_id: str | None
    failure_reason: str | None
    duration_seconds: float | None
    created_at: str


class ValidationResultResponse(BaseModel):
    result_id: str
    job_id: str
    verdict: str
    final_confidence: float
    signal_count: int
    correlation_count: int
    stages_passed: list[str]
    is_reachable: bool
    http_status: int | None
    middleware_score: float
    missing_headers: list[str]
    cors_wildcard: bool
    has_reflected_input: bool
    has_stack_trace: bool
    has_json_error_leak: bool
    poc_triggered: bool
    poc_type: str
    evidence_count: int


class EvidenceBreakdown(BaseModel):
    reachability: dict[str, Any]
    middleware: dict[str, Any]
    parser: dict[str, Any]
    poc: dict[str, Any]
    inference_score_estimate: float
    correlation_count: int


# ── Dependency helpers ────────────────────────────────────────────────────────

def _get_service(request: Request) -> ExposureValidationService:
    return request.app.state.eve_service


def _get_job_repo(request: Request) -> ValidationJobRepository:
    return request.app.state.job_repo


def _get_result_repo(request: Request) -> ValidationResultRepository:
    return request.app.state.result_repo


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/jobs", status_code=status.HTTP_202_ACCEPTED)
async def submit_job(
    body: ValidateRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> dict[str, str]:
    svc = _get_service(request)
    cmd = ValidateExposureCommand(
        tenant_id=body.tenant_id,
        target_url=body.target_url,
        exposure_type=body.exposure_type,
        signal_source=body.signal_source,
        endpoint_path=body.endpoint_path,
        method=body.method,
        param_names=tuple(body.param_names),
        confidence_hint=body.confidence_hint,
        correlation_id=body.correlation_id,
        timeout_seconds=body.timeout_seconds,
    )
    background_tasks.add_task(svc.validate, cmd)
    return {"status": "accepted", "message": "Validation job submitted."}


@router.post("/jobs/sync", status_code=status.HTTP_200_OK, include_in_schema=False)
async def submit_job_sync(
    body: ValidateRequest,
    request: Request,
) -> dict[str, str]:
    svc = _get_service(request)
    cmd = ValidateExposureCommand(
        tenant_id=body.tenant_id,
        target_url=body.target_url,
        exposure_type=body.exposure_type,
        signal_source=body.signal_source,
        endpoint_path=body.endpoint_path,
        method=body.method,
        param_names=tuple(body.param_names),
        confidence_hint=body.confidence_hint,
        correlation_id=body.correlation_id,
        timeout_seconds=body.timeout_seconds,
    )
    job_id = await svc.validate(cmd)
    return {"job_id": job_id}


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job(job_id: str, request: Request) -> JobStatusResponse:
    repo = _get_job_repo(request)
    job = await repo.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.job_id,
        tenant_id=job.tenant_id,
        target_url=job.target_url,
        exposure_type=job.exposure_type.value,
        status=job.status.value,
        result_id=job.result_id,
        failure_reason=job.failure_reason,
        duration_seconds=job.duration_seconds,
        created_at=job.created_at.isoformat(),
    )


@router.get("/jobs", response_model=list[JobStatusResponse])
async def list_jobs(
    request: Request,
    tenant_id: Annotated[str, Query()],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[JobStatusResponse]:
    from cves_db.types import TenantId
    repo = _get_job_repo(request)
    jobs = await repo.list_by_tenant(
        TenantId(uuid.UUID(tenant_id)), limit=limit, offset=offset
    )
    return [
        JobStatusResponse(
            job_id=j.job_id,
            tenant_id=j.tenant_id,
            target_url=j.target_url,
            exposure_type=j.exposure_type.value,
            status=j.status.value,
            result_id=j.result_id,
            failure_reason=j.failure_reason,
            duration_seconds=j.duration_seconds,
            created_at=j.created_at.isoformat(),
        )
        for j in jobs
    ]


@router.get("/jobs/{job_id}/result", response_model=ValidationResultResponse)
async def get_result(job_id: str, request: Request) -> ValidationResultResponse:
    repo = _get_result_repo(request)
    result = await repo.get_by_job(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")
    return ValidationResultResponse(
        result_id=result.result_id,
        job_id=result.job_id,
        verdict=result.verdict.value,
        final_confidence=result.final_confidence,
        signal_count=result.signal_count,
        correlation_count=result.correlation_count,
        stages_passed=list(result.stages_passed),
        is_reachable=result.reachability_probe.is_reachable,
        http_status=result.reachability_probe.http_status,
        middleware_score=result.middleware_findings.score,
        missing_headers=list(result.middleware_findings.missing_headers),
        cors_wildcard=result.middleware_findings.cors_allows_wildcard,
        has_reflected_input=result.parser_findings.has_reflected_input,
        has_stack_trace=result.parser_findings.has_stack_trace,
        has_json_error_leak=result.parser_findings.has_json_error_leak,
        poc_triggered=result.poc_result.triggered,
        poc_type=result.poc_result.probe_type,
        evidence_count=result.evidence_count,
    )


@router.get("/jobs/{job_id}/evidence", response_model=EvidenceBreakdown)
async def get_evidence(job_id: str, request: Request) -> EvidenceBreakdown:
    repo = _get_result_repo(request)
    result = await repo.get_by_job(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found")

    rp = result.reachability_probe
    mf = result.middleware_findings
    pf = result.parser_findings
    poc = result.poc_result

    return EvidenceBreakdown(
        reachability={
            "is_reachable": rp.is_reachable,
            "http_status": rp.http_status,
            "response_time_ms": rp.response_time_ms,
            "required_playwright": rp.required_playwright,
            "error": rp.error,
        },
        middleware={
            "score": mf.score,
            "csp_present": mf.csp_present,
            "hsts_present": mf.hsts_present,
            "x_frame_options": mf.x_frame_options,
            "cors_wildcard": mf.cors_allows_wildcard,
            "cors_credentials_wildcard": mf.cors_allows_credentials_with_wildcard,
            "missing_headers": list(mf.missing_headers),
        },
        parser={
            "content_type": pf.content_type,
            "has_reflected_input": pf.has_reflected_input,
            "reflected_in": pf.reflected_in,
            "has_json_error_leak": pf.has_json_error_leak,
            "has_stack_trace": pf.has_stack_trace,
            "has_debug_info": pf.has_debug_info,
            "risk_indicators": list(pf.risk_indicators),
            "risk_score": pf.risk_score,
        },
        poc={
            "probe_type": poc.probe_type,
            "triggered": poc.triggered,
            "evidence": poc.evidence,
            "safe": poc.safe,
        },
        inference_score_estimate=result.final_confidence,
        correlation_count=result.correlation_count,
    )
