"""Neo4j implementation of GraphRepository.

Maps domain GraphNode / GraphEdge objects to Cypher upserts and translates
Neo4j query results into domain value objects.

All queries filter by `tenant_id` for logical multi-tenant isolation.
"""
from __future__ import annotations

from typing import Any

import structlog

from asset_graph.domain.entities.graph_edge import EdgeType, GraphEdge
from asset_graph.domain.entities.graph_node import GraphNode, NodeType
from asset_graph.domain.value_objects.attack_path import AttackPath, PathNode
from asset_graph.domain.value_objects.dependency_risk import DependencyRisk
from asset_graph.domain.value_objects.propagation_result import (
    ExposurePropagation,
    PropagationHop,
)
from asset_graph.domain.value_objects.trust_chain import TrustChain, TrustLink
from asset_graph.infrastructure.neo4j import cypher_queries as Q
from asset_graph.infrastructure.neo4j.driver import AsyncNeo4jDriver

log = structlog.get_logger(__name__)

# ── Node upsert cypher map ─────────────────────────────────────────────────────

_NODE_CYPHER: dict[NodeType, str] = {
    NodeType.ASSET: Q.UPSERT_ASSET,
    NodeType.ENDPOINT: Q.UPSERT_ENDPOINT,
    NodeType.SERVICE: Q.UPSERT_SERVICE,
    NodeType.DEPENDENCY: Q.UPSERT_DEPENDENCY,
    NodeType.ROUTE: Q.UPSERT_ROUTE,
}


class Neo4jGraphRepository:
    """Satisfies the `GraphRepository` port using the async neo4j driver."""

    def __init__(self, driver: AsyncNeo4jDriver) -> None:
        self._driver = driver

    # ── Mutations ──────────────────────────────────────────────────────────

    async def upsert_node(self, node: GraphNode) -> None:
        cypher = _NODE_CYPHER.get(node.label, Q.UPSERT_GENERIC_NODE)
        params: dict[str, Any] = {
            "node_id": node.node_id,
            "tenant_id": node.tenant_id,
            **node.properties,
        }
        # Fill any missing optional params with None so Cypher doesn't fail
        _fill_missing(params, node.label)
        async with self._driver.session() as s:
            await s.run(cypher, **params)
        log.debug("age.graph.node_upserted", node_id=node.node_id, label=node.label)

    async def upsert_edge(self, edge: GraphEdge) -> None:
        # Edge upsert uses a dynamic edge type — format Cypher template
        cypher = Q.UPSERT_EDGE.format(edge_type=edge.edge_type.value)
        async with self._driver.session() as s:
            await s.run(
                cypher,
                from_id=edge.from_id,
                to_id=edge.to_id,
                properties=edge.properties,
            )
        log.debug(
            "age.graph.edge_upserted",
            from_id=edge.from_id,
            to_id=edge.to_id,
            edge_type=edge.edge_type,
        )

    async def update_endpoint_confidence(
        self, endpoint_id: str, confidence: float, verdict: str
    ) -> None:
        async with self._driver.session() as s:
            await s.run(
                Q.UPDATE_ENDPOINT_CONFIDENCE,
                endpoint_id=endpoint_id,
                confidence=confidence,
                verdict=verdict,
            )

    # ── Attack Paths ───────────────────────────────────────────────────────

    async def find_attack_paths(
        self, tenant_id: str, max_paths: int = 20
    ) -> list[AttackPath]:
        async with self._driver.session() as s:
            result = await s.run(Q.ATTACK_PATHS, tid=tenant_id, max_paths=max_paths)
            records = await result.data()

        paths: list[AttackPath] = []
        for row in records:
            path_nodes = tuple(
                PathNode(
                    node_id=n["node_id"],
                    label=n["label"],
                    url=n.get("url"),
                    host=n.get("host"),
                )
                for n in row["path_nodes"]
            )
            # Risk score: inversely proportional to hops, capped at 1
            risk = max(0.0, min(1.0, 1.0 - (row["hops"] - 1) * 0.12))
            paths.append(
                AttackPath(
                    source_endpoint_id=row["src_id"],
                    target_asset_id=row["dst_id"],
                    hops=row["hops"],
                    nodes=path_nodes,
                    risk_score=risk,
                )
            )
        return paths

    # ── Trust Chains ───────────────────────────────────────────────────────

    async def find_trust_chains(
        self, tenant_id: str, asset_id: str, max_depth: int = 10
    ) -> list[TrustChain]:
        async with self._driver.session() as s:
            result = await s.run(
                Q.TRUST_CHAINS,
                asset_id=asset_id,
                tid=tenant_id,
                max_depth=max_depth,
            )
            records = await result.data()

        chains: list[TrustChain] = []
        for row in records:
            links = tuple(
                TrustLink(
                    from_asset_id=lnk["from_asset_id"],
                    to_asset_id=lnk["to_asset_id"],
                    trust_type=lnk.get("trust_type", "UNKNOWN"),
                    origin=lnk.get("origin"),
                )
                for lnk in row["links"]
            )
            chains.append(
                TrustChain(
                    root_asset_id=asset_id,
                    chain=links,
                    depth=row["depth"],
                    terminal_asset_ids=tuple(row.get("terminals", [])),
                )
            )
        return chains

    # ── Exposure Propagation ───────────────────────────────────────────────

    async def find_exposure_propagation(
        self, tenant_id: str, max_depth: int = 5
    ) -> list[ExposurePropagation]:
        """Attempts APOC query first; falls back to native Cypher."""
        try:
            return await self._propagation_apoc(tenant_id, max_depth)
        except Exception as exc:
            log.warning(
                "age.graph.apoc_propagation_failed_fallback",
                error=str(exc),
            )
            return await self._propagation_native(tenant_id, max_depth)

    async def _propagation_apoc(
        self, tenant_id: str, max_depth: int
    ) -> list[ExposurePropagation]:
        async with self._driver.session() as s:
            result = await s.run(
                Q.EXPOSURE_PROPAGATION_APOC,
                tid=tenant_id,
                max_depth=max_depth,
            )
            records = await result.data()
        return _group_propagation(records, max_depth)

    async def _propagation_native(
        self, tenant_id: str, max_depth: int
    ) -> list[ExposurePropagation]:
        async with self._driver.session() as s:
            result = await s.run(
                Q.EXPOSURE_PROPAGATION_NATIVE,
                tid=tenant_id,
                max_depth=max_depth,
            )
            records = await result.data()
        return _group_propagation(records, max_depth)

    # ── Dependency Risk ────────────────────────────────────────────────────

    async def find_dependency_risks(self, tenant_id: str) -> list[DependencyRisk]:
        async with self._driver.session() as s:
            result = await s.run(Q.DEPENDENCY_RISKS, tid=tenant_id)
            records = await result.data()

        return [
            DependencyRisk(
                asset_id=row["asset_id"],
                asset_url=row.get("asset_url"),
                dep_id=row["dep_id"],
                name=row["name"],
                version=row.get("version", "unknown"),
                ecosystem=row.get("ecosystem", "unknown"),
                cve_ids=tuple(c for c in (row.get("cve_ids") or []) if c),
                max_cvss=row.get("max_cvss"),
            )
            for row in records
        ]

    # ── Infra Map ──────────────────────────────────────────────────────────

    async def find_infra_map(self, tenant_id: str) -> dict[str, Any]:
        async with self._driver.session() as s:
            result = await s.run(Q.INFRA_MAP, tid=tenant_id)
            records = await result.data()
        return {"nodes": records}

    # ── Stats ──────────────────────────────────────────────────────────────

    async def get_stats(self, tenant_id: str) -> dict[str, int]:
        stats: dict[str, int] = {}
        async with self._driver.session() as s:
            node_result = await s.run(Q.STATS_NODES, tid=tenant_id)
            for row in await node_result.data():
                label = row.get("label") or "Unknown"
                stats[f"nodes:{label}"] = row["cnt"]

            edge_result = await s.run(Q.STATS_EDGES, tid=tenant_id)
            for row in await edge_result.data():
                stats[f"edges:{row['edge_type']}"] = row["cnt"]
        return stats

    # ── Asset List ─────────────────────────────────────────────────────────

    async def list_assets(
        self, tenant_id: str, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        async with self._driver.session() as s:
            result = await s.run(
                Q.LIST_ASSETS, tid=tenant_id, limit=limit, offset=offset
            )
            return await result.data()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _fill_missing(params: dict[str, Any], label: NodeType) -> None:
    """Ensure optional Cypher parameters have at least a None value."""
    defaults: dict[NodeType, list[str]] = {
        NodeType.ASSET: ["url", "host", "port", "scheme", "asset_type"],
        NodeType.ENDPOINT: [
            "url", "path", "method", "exposure_type", "verdict",
            "confidence", "poc_triggered",
        ],
        NodeType.SERVICE: ["host", "port", "protocol", "internal"],
        NodeType.DEPENDENCY: ["name", "version", "ecosystem"],
        NodeType.ROUTE: ["path", "router_type", "component_hint"],
        NodeType.TENANT: [],
    }
    for key in defaults.get(label, []):
        params.setdefault(key, None)


def _group_propagation(
    records: list[dict[str, Any]], max_depth: int
) -> list[ExposurePropagation]:
    """Group flat propagation rows by origin endpoint."""
    grouped: dict[str, list[PropagationHop]] = {}
    for row in records:
        origin = row["origin_endpoint_id"]
        grouped.setdefault(origin, [])
        depth = row.get("hop_distance", 1)
        grouped[origin].append(
            PropagationHop(
                asset_id=row["asset_id"],
                url=row.get("asset_url"),
                host=row.get("asset_host"),
                hop_distance=depth,
                reached_via=row.get("reached_via", "CALLS"),
            )
        )

    result: list[ExposurePropagation] = []
    for endpoint_id, hops in grouped.items():
        actual_depth = max((h.hop_distance for h in hops), default=0)
        result.append(
            ExposurePropagation(
                origin_endpoint_id=endpoint_id,
                tenant_id="",  # tenant filtered at query level
                affected_assets=tuple(hops),
                propagation_depth=actual_depth,
                max_hops_reached=actual_depth >= max_depth,
            )
        )
    return result
