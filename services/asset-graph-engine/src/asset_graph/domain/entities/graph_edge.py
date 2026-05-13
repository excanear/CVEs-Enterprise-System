"""Domain entity: Graph Edge.

Represents a directed relationship in the asset graph before Neo4j persistence.
Zero external dependencies — pure Python dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class EdgeType(StrEnum):
    """Relationship types used in the Neo4j graph."""

    EXPOSES = "EXPOSES"            # (Asset)→(Endpoint)
    CALLS = "CALLS"                # (Asset)→(Asset)  — RAE intercepted APIs
    TRUSTS = "TRUSTS"              # (Asset)→(Asset)  — CORS / OAuth / JWT issuer
    DEPENDS_ON = "DEPENDS_ON"      # (Asset)→(Dependency)
    HOSTED_ON = "HOSTED_ON"        # (Asset)→(Service)
    CONNECTS_TO = "CONNECTS_TO"    # (Service)→(Service)
    HAS_ROUTE = "HAS_ROUTE"        # (Asset)→(Route)
    LAZY_LOADS = "LAZY_LOADS"      # (Route)→(Route)
    BELONGS_TO = "BELONGS_TO"      # any→(Tenant)


@dataclass
class GraphEdge:
    """Canonical representation of a Neo4j relationship before persistence.

    Uses business-keys (`from_id`, `to_id`) that match ``GraphNode.node_id``.
    The tuple (from_id, edge_type, to_id) acts as natural key for MERGE.
    """

    from_id: str
    to_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # ── Convenience constructors ───────────────────────────────────────────

    @classmethod
    def exposes(cls, asset_id: str, endpoint_id: str) -> "GraphEdge":
        return cls(from_id=asset_id, to_id=endpoint_id, edge_type=EdgeType.EXPOSES)

    @classmethod
    def calls(
        cls,
        caller_id: str,
        callee_id: str,
        method: str = "GET",
        intercepted_at: str | None = None,
    ) -> "GraphEdge":
        return cls(
            from_id=caller_id,
            to_id=callee_id,
            edge_type=EdgeType.CALLS,
            properties={"method": method, "intercepted_at": intercepted_at},
        )

    @classmethod
    def trusts(
        cls,
        truster_id: str,
        trusted_id: str,
        trust_type: str = "CORS",
        origin: str | None = None,
    ) -> "GraphEdge":
        return cls(
            from_id=truster_id,
            to_id=trusted_id,
            edge_type=EdgeType.TRUSTS,
            properties={"trust_type": trust_type, "origin": origin},
        )

    @classmethod
    def depends_on(
        cls, asset_id: str, dep_id: str, version: str | None = None
    ) -> "GraphEdge":
        return cls(
            from_id=asset_id,
            to_id=dep_id,
            edge_type=EdgeType.DEPENDS_ON,
            properties={"version": version},
        )

    @classmethod
    def has_route(cls, asset_id: str, route_id: str) -> "GraphEdge":
        return cls(from_id=asset_id, to_id=route_id, edge_type=EdgeType.HAS_ROUTE)

    @classmethod
    def lazy_loads(cls, parent_route_id: str, child_route_id: str) -> "GraphEdge":
        return cls(
            from_id=parent_route_id,
            to_id=child_route_id,
            edge_type=EdgeType.LAZY_LOADS,
        )
