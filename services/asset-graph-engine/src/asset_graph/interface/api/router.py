"""FastAPI router for Asset Graph Engine.

Endpoints (prefix /graph):
  POST  /graph/ingest                — manual event ingestion (202)
  GET   /graph/assets                — list Asset nodes by tenant
  GET   /graph/attack-paths          — allShortestPaths from TRUE_POSITIVE endpoints
  GET   /graph/trust-chains          — transitive TRUSTS from an asset
  GET   /graph/exposure-propagation  — APOC BFS via CALLS/TRUSTS
  GET   /graph/dependencies          — DEPENDS_ON graph with optional CVE enrichment
  GET   /graph/infra                 — HOSTED_ON + CONNECTS_TO map
  GET   /graph/stats                 — node/edge counts by tenant
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from asset_graph.application.commands import (
    IngestEnvelopeCommand,
    QueryAttackPathsCommand,
    QueryDependenciesCommand,
    QueryInfraMapCommand,
    QueryPropagationCommand,
    QueryStatsCommand,
    QueryTrustChainsCommand,
)
from asset_graph.application.asset_graph_service import AssetGraphService

router = APIRouter(prefix="/graph", tags=["asset-graph"])


# ── Request / Response schemas ────────────────────────────────────────────────

class IngestRequest(BaseModel):
    tenant_id: str
    event_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str = ""


class AssetResponse(BaseModel):
    node_id: str
    url: str | None
    host: str | None
    port: int | None
    scheme: str | None
    asset_type: str | None


class PathNodeResponse(BaseModel):
    node_id: str
    label: str
    url: str | None
    host: str | None


class AttackPathResponse(BaseModel):
    source_endpoint_id: str
    target_asset_id: str
    hops: int
    risk_score: float
    nodes: list[PathNodeResponse]


class TrustLinkResponse(BaseModel):
    from_asset_id: str
    to_asset_id: str
    trust_type: str
    origin: str | None


class TrustChainResponse(BaseModel):
    root_asset_id: str
    depth: int
    terminal_asset_ids: list[str]
    chain: list[TrustLinkResponse]


class PropagationHopResponse(BaseModel):
    asset_id: str
    url: str | None
    host: str | None
    hop_distance: int
    reached_via: str


class PropagationResponse(BaseModel):
    origin_endpoint_id: str
    affected_count: int
    propagation_depth: int
    max_hops_reached: bool
    affected_assets: list[PropagationHopResponse]


class DependencyRiskResponse(BaseModel):
    asset_id: str
    asset_url: str | None
    dep_id: str
    name: str
    version: str
    ecosystem: str
    has_known_cves: bool
    cve_ids: list[str]
    max_cvss: float | None


# ── Dependency helper ─────────────────────────────────────────────────────────

def _get_service(request: Request) -> AssetGraphService:
    return request.app.state.age_service


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(body: IngestRequest, request: Request) -> dict[str, str]:
    """Manually ingest a single event envelope into the asset graph."""
    svc = _get_service(request)
    cmd = IngestEnvelopeCommand(
        event_type=body.event_type,
        tenant_id=body.tenant_id,
        payload=body.payload,
        correlation_id=body.correlation_id,
    )
    await svc.ingest_manual(cmd)
    return {"status": "accepted", "event_type": body.event_type}


@router.get("/assets", response_model=list[AssetResponse])
async def list_assets(
    request: Request,
    tenant_id: Annotated[str, Query()],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AssetResponse]:
    """List Asset nodes for a tenant with basic pagination."""
    svc = _get_service(request)
    rows = await svc.list_assets(tenant_id=tenant_id, limit=limit, offset=offset)
    return [
        AssetResponse(
            node_id=r["node_id"],
            url=r.get("url"),
            host=r.get("host"),
            port=r.get("port"),
            scheme=r.get("scheme"),
            asset_type=r.get("asset_type"),
        )
        for r in rows
    ]


@router.get("/attack-paths", response_model=list[AttackPathResponse])
async def get_attack_paths(
    request: Request,
    tenant_id: Annotated[str, Query()],
    max_paths: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AttackPathResponse]:
    """Return allShortestPaths from TRUE_POSITIVE Endpoints to reachable Assets."""
    svc = _get_service(request)
    paths = await svc.attack_paths(
        QueryAttackPathsCommand(tenant_id=tenant_id, max_paths=max_paths)
    )
    return [
        AttackPathResponse(
            source_endpoint_id=p.source_endpoint_id,
            target_asset_id=p.target_asset_id,
            hops=p.hops,
            risk_score=p.risk_score,
            nodes=[
                PathNodeResponse(
                    node_id=n.node_id,
                    label=n.label,
                    url=n.url,
                    host=n.host,
                )
                for n in p.nodes
            ],
        )
        for p in paths
    ]


@router.get("/trust-chains", response_model=list[TrustChainResponse])
async def get_trust_chains(
    request: Request,
    tenant_id: Annotated[str, Query()],
    asset_id: Annotated[str, Query()],
    max_depth: Annotated[int, Query(ge=1, le=15)] = 10,
) -> list[TrustChainResponse]:
    """Return transitive TRUSTS chains (CORS / OAuth / JWT) from a given Asset."""
    svc = _get_service(request)
    chains = await svc.trust_chains(
        QueryTrustChainsCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            max_depth=max_depth,
        )
    )
    return [
        TrustChainResponse(
            root_asset_id=c.root_asset_id,
            depth=c.depth,
            terminal_asset_ids=list(c.terminal_asset_ids),
            chain=[
                TrustLinkResponse(
                    from_asset_id=lnk.from_asset_id,
                    to_asset_id=lnk.to_asset_id,
                    trust_type=lnk.trust_type,
                    origin=lnk.origin,
                )
                for lnk in c.chain
            ],
        )
        for c in chains
    ]


@router.get("/exposure-propagation", response_model=list[PropagationResponse])
async def get_exposure_propagation(
    request: Request,
    tenant_id: Annotated[str, Query()],
    max_depth: Annotated[int, Query(ge=1, le=10)] = 5,
) -> list[PropagationResponse]:
    """BFS traversal via CALLS/TRUSTS from all TRUE_POSITIVE Endpoints (uses APOC)."""
    svc = _get_service(request)
    results = await svc.propagation(
        QueryPropagationCommand(tenant_id=tenant_id, max_depth=max_depth)
    )
    return [
        PropagationResponse(
            origin_endpoint_id=r.origin_endpoint_id,
            affected_count=r.affected_count,
            propagation_depth=r.propagation_depth,
            max_hops_reached=r.max_hops_reached,
            affected_assets=[
                PropagationHopResponse(
                    asset_id=h.asset_id,
                    url=h.url,
                    host=h.host,
                    hop_distance=h.hop_distance,
                    reached_via=h.reached_via,
                )
                for h in r.affected_assets
            ],
        )
        for r in results
    ]


@router.get("/dependencies", response_model=list[DependencyRiskResponse])
async def get_dependencies(
    request: Request,
    tenant_id: Annotated[str, Query()],
) -> list[DependencyRiskResponse]:
    """List runtime dependencies with CVE enrichment (when HAS_CVE edges exist)."""
    svc = _get_service(request)
    risks = await svc.dependency_risks(QueryDependenciesCommand(tenant_id=tenant_id))
    return [
        DependencyRiskResponse(
            asset_id=r.asset_id,
            asset_url=r.asset_url,
            dep_id=r.dep_id,
            name=r.name,
            version=r.version,
            ecosystem=r.ecosystem,
            has_known_cves=r.has_known_cves,
            cve_ids=list(r.cve_ids),
            max_cvss=r.max_cvss,
        )
        for r in risks
    ]


@router.get("/infra", response_model=dict[str, Any])
async def get_infra_map(
    request: Request,
    tenant_id: Annotated[str, Query()],
) -> dict[str, Any]:
    """Return HOSTED_ON + CONNECTS_TO infrastructure map for a tenant."""
    svc = _get_service(request)
    return await svc.infra_map(QueryInfraMapCommand(tenant_id=tenant_id))


@router.get("/stats", response_model=dict[str, int])
async def get_stats(
    request: Request,
    tenant_id: Annotated[str, Query()],
) -> dict[str, int]:
    """Return node and edge counts per label and relationship type for a tenant."""
    svc = _get_service(request)
    return await svc.stats(QueryStatsCommand(tenant_id=tenant_id))
