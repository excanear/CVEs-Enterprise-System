"""Domain ports (Protocols) for Asset Graph Engine.

All infrastructure adapters must satisfy one of these interfaces.
Zero external dependencies — plain `typing.Protocol`.
"""
from __future__ import annotations

from typing import Any, Protocol

from asset_graph.domain.entities.graph_edge import GraphEdge
from asset_graph.domain.entities.graph_node import GraphNode
from asset_graph.domain.value_objects.attack_path import AttackPath
from asset_graph.domain.value_objects.dependency_risk import DependencyRisk
from asset_graph.domain.value_objects.propagation_result import ExposurePropagation
from asset_graph.domain.value_objects.trust_chain import TrustChain


class GraphRepository(Protocol):
    """Abstracts Neo4j write + read operations."""

    # ── Mutations ──────────────────────────────────────────────────────────
    async def upsert_node(self, node: GraphNode) -> None: ...
    async def upsert_edge(self, edge: GraphEdge) -> None: ...
    async def update_endpoint_confidence(
        self, endpoint_id: str, confidence: float, verdict: str
    ) -> None: ...

    # ── Queries ────────────────────────────────────────────────────────────
    async def find_attack_paths(
        self, tenant_id: str, max_paths: int = 20
    ) -> list[AttackPath]: ...

    async def find_trust_chains(
        self, tenant_id: str, asset_id: str, max_depth: int = 10
    ) -> list[TrustChain]: ...

    async def find_exposure_propagation(
        self, tenant_id: str, max_depth: int = 5
    ) -> list[ExposurePropagation]: ...

    async def find_dependency_risks(
        self, tenant_id: str
    ) -> list[DependencyRisk]: ...

    async def find_infra_map(
        self, tenant_id: str
    ) -> dict[str, Any]: ...

    async def get_stats(self, tenant_id: str) -> dict[str, int]: ...

    async def list_assets(
        self, tenant_id: str, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]: ...


class IngestionJobRepository(Protocol):
    """Tracks Kafka event ingestion jobs in PostgreSQL."""

    async def record(self, job_id: str, tenant_id: str, event_type: str) -> None: ...
    async def count_by_tenant(self, tenant_id: str) -> int: ...


class GraphEventPublisher(Protocol):
    """Publishes AGE domain events to Kafka."""

    async def publish_node_upserted(self, node: GraphNode) -> None: ...
    async def publish_attack_path(self, path: AttackPath, tenant_id: str) -> None: ...
    async def publish_propagation(
        self, propagation: ExposurePropagation
    ) -> None: ...
