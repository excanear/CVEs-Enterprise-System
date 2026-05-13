"""Domain entity: Graph Node.

Represents a node in the asset graph before it is persisted to Neo4j.
Zero external dependencies — pure Python dataclass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    """Labels used in the Neo4j graph."""

    ASSET = "Asset"
    ENDPOINT = "Endpoint"
    SERVICE = "Service"
    DEPENDENCY = "Dependency"
    ROUTE = "Route"
    TENANT = "Tenant"


@dataclass
class GraphNode:
    """Canonical representation of a Neo4j node before persistence.

    `node_id` is the business-key used in MERGE operations (not the internal
    Neo4j element id). Convention:
      - Asset      → sha256(tenant_id + url)
      - Endpoint   → sha256(tenant_id + url + path + method)
      - Service    → sha256(tenant_id + host + str(port))
      - Dependency → sha256(name + version + ecosystem)
      - Route      → sha256(tenant_id + path + router_type)
    """

    node_id: str
    tenant_id: str
    label: NodeType
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # ── Convenience constructors ───────────────────────────────────────────

    @classmethod
    def asset(
        cls,
        node_id: str,
        tenant_id: str,
        url: str,
        host: str,
        port: int | None = None,
        scheme: str = "https",
        asset_type: str = "WEB_APP",
    ) -> "GraphNode":
        return cls(
            node_id=node_id,
            tenant_id=tenant_id,
            label=NodeType.ASSET,
            properties={
                "url": url,
                "host": host,
                "port": port,
                "scheme": scheme,
                "asset_type": asset_type,
            },
        )

    @classmethod
    def endpoint(
        cls,
        node_id: str,
        tenant_id: str,
        url: str,
        path: str,
        method: str,
        exposure_type: str,
        verdict: str = "UNKNOWN",
        confidence: float = 0.0,
        poc_triggered: bool = False,
    ) -> "GraphNode":
        return cls(
            node_id=node_id,
            tenant_id=tenant_id,
            label=NodeType.ENDPOINT,
            properties={
                "url": url,
                "path": path,
                "method": method,
                "exposure_type": exposure_type,
                "verdict": verdict,
                "confidence": confidence,
                "poc_triggered": poc_triggered,
            },
        )

    @classmethod
    def dependency(
        cls,
        node_id: str,
        tenant_id: str,
        name: str,
        version: str,
        ecosystem: str,
    ) -> "GraphNode":
        return cls(
            node_id=node_id,
            tenant_id=tenant_id,
            label=NodeType.DEPENDENCY,
            properties={
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
            },
        )

    @classmethod
    def route(
        cls,
        node_id: str,
        tenant_id: str,
        path: str,
        router_type: str,
        component_hint: str | None = None,
    ) -> "GraphNode":
        return cls(
            node_id=node_id,
            tenant_id=tenant_id,
            label=NodeType.ROUTE,
            properties={
                "path": path,
                "router_type": router_type,
                "component_hint": component_hint,
            },
        )
