"""JSI (JavaScript Intelligence) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


JSI_JS_TOPIC = "jsi.js.events"

JSI_EVENT_TYPES: dict[str, str] = {
    "js_bundle_analyzed": "jsi.js.bundle_analyzed",
    "js_routes_discovered": "jsi.js.routes_discovered",
    "js_dependency_graph_built": "jsi.js.dependency_graph_built",
}


class _JSIBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class JSBundleAnalyzedPayload(_JSIBase):
    """Payload for event_type='jsi.js.bundle_analyzed'.

    Emitted once per JS bundle discovered and analyzed.
    """

    job_id: uuid.UUID
    asset_id: uuid.UUID
    bundle_url: str
    content_hash: str
    size_bytes: int
    is_minified: bool
    bundler: str
    chunk_id: str | None = None
    source_map_url: str | None = None
    has_source_map: bool = False


class RouteEntry(_JSIBase):
    """A single inferred route within a JS bundle."""

    path: str
    router_type: str
    component_hint: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    discovered_in_chunk: str
    lazy_chunks: list[str] = Field(default_factory=list)


class JSRoutesDiscoveredPayload(_JSIBase):
    """Payload for event_type='jsi.js.routes_discovered'.

    Emitted once per job when route inference completes.
    """

    job_id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str
    routes: list[RouteEntry] = Field(default_factory=list)
    total_routes: int = 0
    bundler: str
    router_type_detected: str | None = None


class JSDependencyGraphBuiltPayload(_JSIBase):
    """Payload for event_type='jsi.js.dependency_graph_built'.

    Emitted once per job when dependency graph construction completes.
    """

    job_id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str
    node_count: int
    edge_count: int
    has_cycles: bool
    entry_points: list[str] = Field(default_factory=list)
    bundler: str
    chunk_count: int
