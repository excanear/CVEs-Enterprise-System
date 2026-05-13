"""Asset Graph Service — application facade.

Single entry point for all graph operations.
Wires GraphIngestionService + 4 analyzers behind a clean public API.
"""
from __future__ import annotations

from typing import Any

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

from asset_graph.application.analysis.attack_path_analyzer import AttackPathAnalyzer
from asset_graph.application.analysis.dependency_risk_analyzer import DependencyRiskAnalyzer
from asset_graph.application.analysis.exposure_propagator import ExposurePropagator
from asset_graph.application.analysis.trust_chain_analyzer import TrustChainAnalyzer
from asset_graph.application.commands import (
    IngestEnvelopeCommand,
    QueryAttackPathsCommand,
    QueryDependenciesCommand,
    QueryInfraMapCommand,
    QueryPropagationCommand,
    QueryStatsCommand,
    QueryTrustChainsCommand,
)
from asset_graph.application.graph_ingestion_service import GraphIngestionService
from asset_graph.domain.ports import GraphEventPublisher, GraphRepository, IngestionJobRepository
from asset_graph.domain.value_objects.attack_path import AttackPath
from asset_graph.domain.value_objects.dependency_risk import DependencyRisk
from asset_graph.domain.value_objects.propagation_result import ExposurePropagation
from asset_graph.domain.value_objects.trust_chain import TrustChain

log = structlog.get_logger(__name__)


class AssetGraphService:
    """Public facade for the Asset Graph Engine application layer."""

    def __init__(
        self,
        graph_repo: GraphRepository,
        job_repo: IngestionJobRepository,
        event_publisher: GraphEventPublisher,
    ) -> None:
        self._graph = graph_repo
        self._ingestion = GraphIngestionService(graph_repo, job_repo, event_publisher)
        self._attack_paths = AttackPathAnalyzer(graph_repo, event_publisher)
        self._trust_chains = TrustChainAnalyzer(graph_repo)
        self._propagator = ExposurePropagator(graph_repo, event_publisher)
        self._dep_risk = DependencyRiskAnalyzer(graph_repo)

    # ── Ingestion ──────────────────────────────────────────────────────────

    async def handle_kafka_signal(self, envelope: DomainEventEnvelope) -> None:
        """Entry point called by the Kafka consumer background task."""
        await self._ingestion.handle_envelope(envelope)

    async def ingest_manual(self, cmd: IngestEnvelopeCommand) -> None:
        """Manually ingest an event (useful for testing / re-processing)."""
        from cves_db.types import uuid7
        import uuid

        fake_envelope = DomainEventEnvelope(
            event_id=uuid7(),
            event_type=cmd.event_type,
            schema_version="1.0.0",
            aggregate_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            aggregate_type="Manual",
            tenant_id=uuid.UUID(cmd.tenant_id),
            correlation_id=uuid7(),
            producer_svc="manual",
            payload=cmd.payload,
        )
        await self._ingestion.handle_envelope(fake_envelope)

    # ── Queries ────────────────────────────────────────────────────────────

    async def attack_paths(self, cmd: QueryAttackPathsCommand) -> list[AttackPath]:
        return await self._attack_paths.analyze(cmd)

    async def trust_chains(self, cmd: QueryTrustChainsCommand) -> list[TrustChain]:
        return await self._trust_chains.analyze(cmd)

    async def propagation(self, cmd: QueryPropagationCommand) -> list[ExposurePropagation]:
        return await self._propagator.propagate(cmd)

    async def dependency_risks(self, cmd: QueryDependenciesCommand) -> list[DependencyRisk]:
        return await self._dep_risk.analyze(cmd)

    async def infra_map(self, cmd: QueryInfraMapCommand) -> dict[str, Any]:
        return await self._graph.find_infra_map(tenant_id=cmd.tenant_id)

    async def stats(self, cmd: QueryStatsCommand) -> dict[str, int]:
        return await self._graph.get_stats(tenant_id=cmd.tenant_id)

    async def list_assets(
        self, tenant_id: str, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        return await self._graph.list_assets(
            tenant_id=tenant_id, limit=limit, offset=offset
        )
