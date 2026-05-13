"""Graph ingestion service.

Routes incoming DomainEventEnvelopes from upstream topics into Neo4j
graph upserts. Each event_type maps to a specific set of MERGE operations.

Mapping table:
  asi.asset.discovered          → upsert_node(:Asset)
  rf.runtime.api_intercepted    → upsert_node(:Asset) x2 + edge CALLS
  rf.runtime.websocket_discovered → upsert_node(:Endpoint) + edge EXPOSES
  jsi.js.routes_discovered      → upsert_node(:Route)[] + HAS_ROUTE + LAZY_LOADS
  jsi.js.bundle_analyzed        → upsert_node(:Dependency)[] + DEPENDS_ON
  eve.exposure.confirmed        → upsert_node(:Endpoint TRUE_POSITIVE) + EXPOSES
  eve.exposure.validation_completed → update_endpoint_confidence
"""
from __future__ import annotations

import hashlib

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope

from asset_graph.domain.entities.graph_edge import EdgeType, GraphEdge
from asset_graph.domain.entities.graph_node import GraphNode, NodeType
from asset_graph.domain.ports import GraphEventPublisher, GraphRepository, IngestionJobRepository

log = structlog.get_logger(__name__)


def _sha(parts: list[str]) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()[:36]


class GraphIngestionService:
    """Maps upstream events to graph mutations."""

    def __init__(
        self,
        graph_repo: GraphRepository,
        job_repo: IngestionJobRepository,
        event_publisher: GraphEventPublisher,
    ) -> None:
        self._graph = graph_repo
        self._jobs = job_repo
        self._publisher = event_publisher

    async def handle_envelope(self, envelope: DomainEventEnvelope) -> None:
        event_type = envelope.event_type
        payload = envelope.payload or {}
        tenant_id = str(envelope.tenant_id)

        try:
            handler = self._HANDLERS.get(event_type)
            if handler is None:
                log.debug("age.ingestion.skip", event_type=event_type)
                return
            await handler(self, tenant_id, payload)
            await self._jobs.record(
                tenant_id=tenant_id,
                event_type=event_type,
                topic=_topic_from_event_type(event_type),
                status="PROCESSED",
                payload_summary={"url": payload.get("url") or payload.get("target_url")},
            )
        except Exception as exc:
            log.error("age.ingestion.error", event_type=event_type, error=str(exc))
            await self._jobs.record(
                tenant_id=tenant_id,
                event_type=event_type,
                topic=_topic_from_event_type(event_type),
                status="FAILED",
                error=str(exc),
            )

    # ── Handlers ───────────────────────────────────────────────────────────

    async def _handle_asset_discovered(self, tenant_id: str, p: dict) -> None:
        url = p.get("url") or p.get("target_url", "")
        host = _extract_host(url)
        node_id = _sha([tenant_id, url])
        node = GraphNode.asset(
            node_id=node_id,
            tenant_id=tenant_id,
            url=url,
            host=host,
            port=_extract_port(url),
            scheme=_extract_scheme(url),
            asset_type=p.get("asset_type", "WEB_APP"),
        )
        await self._graph.upsert_node(node)
        await self._publisher.publish_node_upserted(node)

    async def _handle_api_intercepted(self, tenant_id: str, p: dict) -> None:
        caller_url = p.get("source_url") or p.get("url", "")
        callee_url = p.get("target_url") or p.get("api_url", "")
        if not caller_url or not callee_url:
            return

        caller_id = _sha([tenant_id, caller_url])
        callee_id = _sha([tenant_id, callee_url])

        caller_node = GraphNode.asset(
            node_id=caller_id,
            tenant_id=tenant_id,
            url=caller_url,
            host=_extract_host(caller_url),
        )
        callee_node = GraphNode.asset(
            node_id=callee_id,
            tenant_id=tenant_id,
            url=callee_url,
            host=_extract_host(callee_url),
        )
        await self._graph.upsert_node(caller_node)
        await self._graph.upsert_node(callee_node)
        await self._graph.upsert_edge(
            GraphEdge.calls(
                caller_id=caller_id,
                callee_id=callee_id,
                method=p.get("method", "GET"),
                intercepted_at=p.get("intercepted_at"),
            )
        )

    async def _handle_websocket_discovered(self, tenant_id: str, p: dict) -> None:
        url = p.get("url", "")
        asset_url = _base_url(url)
        asset_id = _sha([tenant_id, asset_url])
        endpoint_id = _sha([tenant_id, url, "WEBSOCKET", "GET"])

        asset_node = GraphNode.asset(
            node_id=asset_id,
            tenant_id=tenant_id,
            url=asset_url,
            host=_extract_host(asset_url),
        )
        endpoint_node = GraphNode.endpoint(
            node_id=endpoint_id,
            tenant_id=tenant_id,
            url=url,
            path=_extract_path(url),
            method="WS",
            exposure_type="WEBSOCKET_UNPROTECTED",
        )
        await self._graph.upsert_node(asset_node)
        await self._graph.upsert_node(endpoint_node)
        await self._graph.upsert_edge(GraphEdge.exposes(asset_id, endpoint_id))

    async def _handle_routes_discovered(self, tenant_id: str, p: dict) -> None:
        target_url = p.get("target_url", "")
        asset_id = _sha([tenant_id, target_url])
        asset_node = GraphNode.asset(
            node_id=asset_id,
            tenant_id=tenant_id,
            url=target_url,
            host=_extract_host(target_url),
        )
        await self._graph.upsert_node(asset_node)

        routes = p.get("routes") or []
        for route_data in routes:
            path = route_data.get("path", "")
            router_type = route_data.get("router_type", "UNKNOWN")
            route_id = _sha([tenant_id, path, router_type])
            route_node = GraphNode.route(
                node_id=route_id,
                tenant_id=tenant_id,
                path=path,
                router_type=router_type,
                component_hint=route_data.get("component_hint"),
            )
            await self._graph.upsert_node(route_node)
            await self._graph.upsert_edge(GraphEdge.has_route(asset_id, route_id))

            for chunk_path in (route_data.get("lazy_chunks") or []):
                chunk_id = _sha([tenant_id, chunk_path, "LAZY"])
                chunk_node = GraphNode.route(
                    node_id=chunk_id,
                    tenant_id=tenant_id,
                    path=chunk_path,
                    router_type="LAZY_CHUNK",
                )
                await self._graph.upsert_node(chunk_node)
                await self._graph.upsert_edge(GraphEdge.lazy_loads(route_id, chunk_id))

    async def _handle_bundle_analyzed(self, tenant_id: str, p: dict) -> None:
        target_url = p.get("target_url", "")
        asset_id = _sha([tenant_id, target_url])
        asset_node = GraphNode.asset(
            node_id=asset_id,
            tenant_id=tenant_id,
            url=target_url,
            host=_extract_host(target_url),
        )
        await self._graph.upsert_node(asset_node)

        deps = p.get("dependencies") or []
        for dep in deps:
            name = dep.get("name", "")
            version = dep.get("version", "")
            ecosystem = dep.get("ecosystem", "npm")
            dep_id = _sha([name, version, ecosystem])
            dep_node = GraphNode.dependency(
                node_id=dep_id,
                tenant_id=tenant_id,
                name=name,
                version=version,
                ecosystem=ecosystem,
            )
            await self._graph.upsert_node(dep_node)
            await self._graph.upsert_edge(
                GraphEdge.depends_on(asset_id, dep_id, version=version)
            )

    async def _handle_exposure_confirmed(self, tenant_id: str, p: dict) -> None:
        target_url = p.get("target_url", "")
        path = p.get("endpoint_path") or _extract_path(target_url)
        method = p.get("method") or "GET"

        asset_id = _sha([tenant_id, target_url])
        endpoint_id = _sha([tenant_id, target_url, path, method])

        asset_node = GraphNode.asset(
            node_id=asset_id,
            tenant_id=tenant_id,
            url=target_url,
            host=_extract_host(target_url),
        )
        endpoint_node = GraphNode.endpoint(
            node_id=endpoint_id,
            tenant_id=tenant_id,
            url=target_url,
            path=path,
            method=method,
            exposure_type=p.get("exposure_type", "EXPOSED_API"),
            verdict="TRUE_POSITIVE",
            confidence=p.get("final_confidence", 1.0),
            poc_triggered=p.get("poc_triggered", False),
        )
        await self._graph.upsert_node(asset_node)
        await self._graph.upsert_node(endpoint_node)
        await self._graph.upsert_edge(GraphEdge.exposes(asset_id, endpoint_id))

        # CORS trust relationship: if CORS_MISCONFIGURATION and origins present
        if p.get("exposure_type") == "CORS_MISCONFIGURATION":
            for origin in (p.get("cors_origins") or []):
                origin_id = _sha([tenant_id, origin])
                origin_node = GraphNode.asset(
                    node_id=origin_id,
                    tenant_id=tenant_id,
                    url=origin,
                    host=_extract_host(origin),
                )
                await self._graph.upsert_node(origin_node)
                await self._graph.upsert_edge(
                    GraphEdge.trusts(
                        truster_id=asset_id,
                        trusted_id=origin_id,
                        trust_type="CORS",
                        origin=origin,
                    )
                )

        await self._publisher.publish_node_upserted(endpoint_node)

    async def _handle_validation_completed(self, tenant_id: str, p: dict) -> None:
        """Update confidence/verdict on existing Endpoint node."""
        target_url = p.get("target_url", "")
        job_id = p.get("job_id", "")
        # endpoint_id must match what was set during exposure_confirmed
        # Using same hash formula — may or may not find the node (benign if missing)
        path = p.get("endpoint_path") or _extract_path(target_url)
        method = p.get("method") or "GET"
        endpoint_id = _sha([tenant_id, target_url, path, method])
        await self._graph.update_endpoint_confidence(
            endpoint_id=endpoint_id,
            confidence=p.get("final_confidence", 0.0),
            verdict=p.get("verdict", "REQUIRES_REVIEW"),
        )

    # ── Handler dispatch table ─────────────────────────────────────────────

    _HANDLERS: dict = {
        "asi.asset.discovered": _handle_asset_discovered,
        "rf.runtime.api_intercepted": _handle_api_intercepted,
        "rf.runtime.websocket_discovered": _handle_websocket_discovered,
        "jsi.js.routes_discovered": _handle_routes_discovered,
        "jsi.js.bundle_analyzed": _handle_bundle_analyzed,
        "eve.exposure.confirmed": _handle_exposure_confirmed,
        "eve.exposure.validation_completed": _handle_validation_completed,
    }


# ── URL helpers ────────────────────────────────────────────────────────────────

def _extract_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _extract_port(url: str) -> int | None:
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.port
    except Exception:
        return None


def _extract_scheme(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).scheme or "https"
    except Exception:
        return "https"


def _extract_path(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _base_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url


def _topic_from_event_type(event_type: str) -> str:
    if event_type.startswith("asi."):
        return "asi.asset.events"
    if event_type.startswith("rf."):
        return "rf.fingerprint.events"
    if event_type.startswith("jsi."):
        return "jsi.js.events"
    if event_type.startswith("eve."):
        return "eve.exposure.events"
    return "unknown"
