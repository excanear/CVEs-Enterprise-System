"""AI Correlation Layer — FastAPI router.

Prefix: /correlation
Endpoints:
  POST /correlation/sessions           — trigger full correlation for tenant
  GET  /correlation/sessions/{id}      — session status
  GET  /correlation/clusters           — evidence clusters
  GET  /correlation/attack-paths/ranked — ranked attack paths
  GET  /correlation/exposures/prioritized — prioritized exposures
  GET  /correlation/remediation/{cluster_id} — remediation plan
  GET  /correlation/risk-summary       — aggregated risk dashboard
"""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from cves_db.types import uuid7

from ai_correlation.application.commands import (
    GetPrioritizedExposuresCommand,
    GetRankedPathsCommand,
    GetRemediationCommand,
    GetRiskSummaryCommand,
    GetSessionCommand,
    ListClustersCommand,
    TriggerCorrelationCommand,
)
from ai_correlation.application.correlation_service import CorrelationService

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/correlation", tags=["correlation"])


def _service(request: Request) -> CorrelationService:
    return request.app.state.correlation_service


# ── Request / Response models ──────────────────────────────────────────────────

class TriggerRequest(BaseModel):
    tenant_id: str = Field(..., description="UUID of the tenant to correlate")


class SessionResponse(BaseModel):
    session_id: str
    tenant_id: str
    status: str
    evidence_count: int
    path_count: int
    cluster_count: int
    prioritized_count: int
    error: str | None
    created_at: str
    updated_at: str
    completed_at: str | None


class EvidenceItemResponse(BaseModel):
    evidence_id: str
    exposure_type: str
    target_url: str
    confidence: float
    poc_triggered: bool
    propagation_depth: int
    hop_count: int
    host: str | None


class ClusterResponse(BaseModel):
    cluster_id: str
    tenant_id: str
    session_id: str
    size: int
    tier: str
    host: str | None
    avg_confidence: float
    poc_triggered_count: int
    exposure_types: list[str]
    items: list[EvidenceItemResponse]


class ScoreComponentsResponse(BaseModel):
    confidence_score: float
    hops_score: float
    poc_score: float
    propagation_score: float
    dep_cvss_score: float


class RankedPathResponse(BaseModel):
    rank: int
    source_endpoint_id: str
    target_asset_id: str
    hops: int
    risk_score: float
    composite_score: float
    path_node_ids: list[str]
    components: ScoreComponentsResponse


class PrioritizedExposureResponse(BaseModel):
    exposure_id: str
    target_url: str
    exposure_type: str
    tier: str
    composite_score: float
    rationale: str


class RemediationResponse(BaseModel):
    cluster_id: str
    exposure_type: str
    steps: list[str]
    llm_enriched: bool
    llm_narrative: str | None


class TopFindingResponse(BaseModel):
    exposure_id: str
    target_url: str
    exposure_type: str
    tier: str
    composite_score: float


class RiskSummaryResponse(BaseModel):
    session_id: str
    tenant_id: str
    total_exposures: int
    counts_by_tier: dict[str, int]
    top_findings: list[TopFindingResponse]
    total_clusters: int
    total_attack_paths: int


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post(
    "/sessions",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SessionResponse,
    summary="Trigger correlation analysis for a tenant",
)
async def trigger_correlation(
    body: TriggerRequest,
    svc: CorrelationService = Depends(_service),
) -> SessionResponse:
    session_id = str(uuid7())
    cmd = TriggerCorrelationCommand(tenant_id=body.tenant_id, session_id=session_id)
    session = await svc.correlate(cmd)
    return _session_to_response(session)


@router.get(
    "/sessions/{session_id}",
    response_model=SessionResponse,
    summary="Get correlation session status",
)
async def get_session(
    session_id: str,
    svc: CorrelationService = Depends(_service),
) -> SessionResponse:
    session = await svc.get_session(GetSessionCommand(session_id=session_id))
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_to_response(session)


@router.get(
    "/clusters",
    response_model=list[ClusterResponse],
    summary="List evidence clusters for a tenant",
)
async def list_clusters(
    tenant_id: str = Query(..., description="Tenant UUID"),
    session_id: str | None = Query(None, description="Filter by session"),
    svc: CorrelationService = Depends(_service),
) -> list[ClusterResponse]:
    clusters = await svc.list_clusters(
        ListClustersCommand(tenant_id=tenant_id, session_id=session_id)
    )
    return [_cluster_to_response(c) for c in clusters]


@router.get(
    "/attack-paths/ranked",
    response_model=list[RankedPathResponse],
    summary="Get ranked attack paths for a tenant",
)
async def get_ranked_paths(
    tenant_id: str = Query(..., description="Tenant UUID"),
    limit: int = Query(50, ge=1, le=200),
    svc: CorrelationService = Depends(_service),
) -> list[RankedPathResponse]:
    paths = await svc.get_ranked_paths(GetRankedPathsCommand(tenant_id=tenant_id, limit=limit))
    return [
        RankedPathResponse(
            rank=p.rank,
            source_endpoint_id=p.source_endpoint_id,
            target_asset_id=p.target_asset_id,
            hops=p.hops,
            risk_score=p.risk_score,
            composite_score=p.composite_score,
            path_node_ids=p.path_node_ids,
            components=ScoreComponentsResponse(
                confidence_score=p.components.confidence_score,
                hops_score=p.components.hops_score,
                poc_score=p.components.poc_score,
                propagation_score=p.components.propagation_score,
                dep_cvss_score=p.components.dep_cvss_score,
            ),
        )
        for p in paths
    ]


@router.get(
    "/exposures/prioritized",
    response_model=list[PrioritizedExposureResponse],
    summary="Get prioritized exposures with risk tier",
)
async def get_prioritized(
    tenant_id: str = Query(..., description="Tenant UUID"),
    tier: str | None = Query(None, description="Filter by tier: CRITICAL|HIGH|MEDIUM|LOW"),
    limit: int = Query(100, ge=1, le=500),
    svc: CorrelationService = Depends(_service),
) -> list[PrioritizedExposureResponse]:
    exposures = await svc.get_prioritized(
        GetPrioritizedExposuresCommand(tenant_id=tenant_id, tier=tier, limit=limit)
    )
    return [
        PrioritizedExposureResponse(
            exposure_id=e.exposure_id,
            target_url=e.target_url,
            exposure_type=e.exposure_type,
            tier=e.tier.value,
            composite_score=e.composite_score,
            rationale=e.rationale,
        )
        for e in exposures
    ]


@router.get(
    "/remediation/{cluster_id}",
    response_model=RemediationResponse,
    summary="Get remediation plan for an evidence cluster",
)
async def get_remediation(
    cluster_id: str,
    tenant_id: str = Query(..., description="Tenant UUID (required for cluster lookup)"),
    svc: CorrelationService = Depends(_service),
) -> RemediationResponse:
    plan = await svc.get_remediation(
        GetRemediationCommand(cluster_id=cluster_id, tenant_id=tenant_id)
    )
    if plan is None:
        raise HTTPException(status_code=404, detail="Cluster not found or no remediation available")
    return RemediationResponse(
        cluster_id=plan.cluster_id,
        exposure_type=plan.exposure_type,
        steps=plan.steps,
        llm_enriched=plan.llm_enriched,
        llm_narrative=plan.llm_narrative,
    )


@router.get(
    "/risk-summary",
    response_model=RiskSummaryResponse,
    summary="Get aggregated risk dashboard for a tenant",
)
async def get_risk_summary(
    tenant_id: str = Query(..., description="Tenant UUID"),
    session_id: str | None = Query(None, description="Filter to a specific session"),
    svc: CorrelationService = Depends(_service),
) -> RiskSummaryResponse:
    summary = await svc.get_risk_summary(
        GetRiskSummaryCommand(tenant_id=tenant_id, session_id=session_id)
    )
    return RiskSummaryResponse(
        session_id=summary.session_id,
        tenant_id=summary.tenant_id,
        total_exposures=summary.total_exposures,
        counts_by_tier=summary.counts_by_tier,
        top_findings=[
            TopFindingResponse(
                exposure_id=f.exposure_id,
                target_url=f.target_url,
                exposure_type=f.exposure_type,
                tier=f.tier.value,
                composite_score=f.composite_score,
            )
            for f in summary.top_findings
        ],
        total_clusters=summary.total_clusters,
        total_attack_paths=summary.total_attack_paths,
    )


# ── Serialization helpers ──────────────────────────────────────────────────────

def _session_to_response(session: Any) -> SessionResponse:
    return SessionResponse(
        session_id=session.session_id,
        tenant_id=session.tenant_id,
        status=session.status.value,
        evidence_count=session.evidence_count,
        path_count=session.path_count,
        cluster_count=session.cluster_count,
        prioritized_count=session.prioritized_count,
        error=session.error,
        created_at=session.created_at.isoformat(),
        updated_at=session.updated_at.isoformat(),
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
    )


def _cluster_to_response(cluster: Any) -> ClusterResponse:
    return ClusterResponse(
        cluster_id=cluster.cluster_id,
        tenant_id=cluster.tenant_id,
        session_id=cluster.session_id,
        size=cluster.size,
        tier=cluster.tier.value,
        host=cluster.host,
        avg_confidence=cluster.avg_confidence,
        poc_triggered_count=cluster.poc_triggered_count,
        exposure_types=cluster.exposure_types,
        items=[
            EvidenceItemResponse(
                evidence_id=i.evidence_id,
                exposure_type=i.exposure_type,
                target_url=i.target_url,
                confidence=i.confidence,
                poc_triggered=i.poc_triggered,
                propagation_depth=i.propagation_depth,
                hop_count=i.hop_count,
                host=i.host,
            )
            for i in cluster.items
        ],
    )
