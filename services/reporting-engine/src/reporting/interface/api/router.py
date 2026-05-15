"""FastAPI router for Reporting Engine — 8 endpoints, prefix /reports."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from reporting.application.commands import (
    ComplianceMappingCommand,
    DownloadReportCommand,
    EvidenceExportCommand,
    ExecutiveSummaryCommand,
    GenerateReportCommand,
    GetReportCommand,
    ListReportsCommand,
    RemediationGuidanceCommand,
)
from reporting.application.reporting_service import ReportingService
from reporting.domain.entities.report import ReportFormat, ReportStatus, ReportType

router = APIRouter(prefix="/reports", tags=["reports"])

# ── Dependency ────────────────────────────────────────────────────────────────


def _svc(request: Request) -> ReportingService:
    return request.app.state.reporting_service


ServiceDep = Annotated[ReportingService, Depends(_svc)]

# ── Request / Response schemas ────────────────────────────────────────────────


class GenerateReportRequest(BaseModel):
    tenant_id: str
    report_type: ReportType
    report_format: ReportFormat
    requested_by: str = "api"


class ReportResponse(BaseModel):
    report_id: str
    tenant_id: str
    report_type: str
    report_format: str
    status: str
    finding_count: int
    error: str | None
    created_at: str
    generated_at: str | None

    model_config = {"from_attributes": True}


def _to_response(report: Any) -> ReportResponse:
    return ReportResponse(
        report_id=report.report_id,
        tenant_id=report.tenant_id,
        report_type=report.report_type.value,
        report_format=report.report_format.value,
        status=report.status.value,
        finding_count=report.finding_count,
        error=report.error,
        created_at=report.created_at.isoformat(),
        generated_at=report.generated_at.isoformat() if report.generated_at else None,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post(
    "/generate",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ReportResponse,
    summary="Trigger async report generation",
)
async def generate_report(body: GenerateReportRequest, svc: ServiceDep) -> ReportResponse:
    cmd = GenerateReportCommand(
        tenant_id=body.tenant_id,
        report_type=body.report_type,
        report_format=body.report_format,
        requested_by=body.requested_by,
    )
    report = await svc.generate_report(cmd)
    return _to_response(report)


@router.get(
    "/executive/summary",
    summary="Synchronous executive summary (JSON)",
)
async def executive_summary(
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> dict:
    return await svc.get_executive_summary(ExecutiveSummaryCommand(tenant_id=tenant_id))


@router.get(
    "/compliance/mapping",
    summary="Compliance mapping for all tenant findings",
)
async def compliance_mapping(
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> list[dict]:
    return await svc.get_compliance_mapping(ComplianceMappingCommand(tenant_id=tenant_id))


@router.get(
    "/evidence/export",
    summary="Raw evidence export (CSV streaming)",
)
async def evidence_export(
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> StreamingResponse:
    csv_content = await svc.get_evidence_export(EvidenceExportCommand(tenant_id=tenant_id))

    async def _stream():
        yield csv_content.encode("utf-8")

    return StreamingResponse(
        _stream(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="evidence_{tenant_id}.csv"'
        },
    )


@router.get(
    "/remediation/guidance",
    summary="Full remediation steps organised by tier",
)
async def remediation_guidance(
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> list[dict]:
    return await svc.get_remediation_guidance(RemediationGuidanceCommand(tenant_id=tenant_id))


@router.get(
    "/",
    response_model=list[ReportResponse],
    summary="List reports for a tenant",
)
async def list_reports(
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[ReportResponse]:
    reports = await svc.list_reports(ListReportsCommand(tenant_id=tenant_id, limit=limit, offset=offset))
    return [_to_response(r) for r in reports]


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Report metadata and status",
)
async def get_report(
    report_id: str,
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> ReportResponse:
    report = await svc.get_report(GetReportCommand(tenant_id=tenant_id, report_id=report_id))
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return _to_response(report)


@router.get(
    "/{report_id}/download",
    summary="Download report file",
)
async def download_report(
    report_id: str,
    tenant_id: Annotated[str, Query(min_length=1)],
    svc: ServiceDep,
) -> Response:
    report = await svc.get_report(DownloadReportCommand(tenant_id=tenant_id, report_id=report_id))
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(status_code=409, detail=f"Report not ready: {report.status.value}")

    fmt = report.report_format
    if fmt == ReportFormat.PDF and report.content_bytes:
        return Response(
            content=report.content_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report_{report_id}.pdf"'
            },
        )
    if fmt == ReportFormat.CSV and report.content:
        return Response(
            content=report.content.encode("utf-8"),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="report_{report_id}.csv"'
            },
        )
    if fmt == ReportFormat.HTML and report.content:
        return Response(
            content=report.content.encode("utf-8"),
            media_type="text/html; charset=utf-8",
        )
    # JSON
    return Response(
        content=(report.content or "{}").encode("utf-8"),
        media_type="application/json",
    )
