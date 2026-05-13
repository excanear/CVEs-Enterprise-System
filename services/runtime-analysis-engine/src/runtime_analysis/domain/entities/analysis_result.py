from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cves_db.types import uuid7

from runtime_analysis.domain.value_objects.dom_snapshot import DOMSnapshot
from runtime_analysis.domain.value_objects.framework_fingerprint import (
    FrameworkFingerprint,
)
from runtime_analysis.domain.value_objects.intercepted_api import InterceptedAPI
from runtime_analysis.domain.value_objects.spa_route import SPARoute
from runtime_analysis.domain.value_objects.websocket_endpoint import WebSocketEndpoint


@dataclass(frozen=True)
class AnalysisResult:
    """Immutable result produced by a completed analysis session."""

    result_id: str
    session_id: str

    intercepted_apis: tuple[InterceptedAPI, ...]
    websocket_endpoints: tuple[WebSocketEndpoint, ...]
    spa_routes: tuple[SPARoute, ...]
    framework_fingerprints: tuple[FrameworkFingerprint, ...]
    dom_snapshot: DOMSnapshot | None
    hydration_markers: dict[str, object]
    created_at: datetime

    @classmethod
    def create(
        cls,
        session_id: str,
        intercepted_apis: list[InterceptedAPI],
        websocket_endpoints: list[WebSocketEndpoint],
        spa_routes: list[SPARoute],
        framework_fingerprints: list[FrameworkFingerprint],
        dom_snapshot: DOMSnapshot | None,
        hydration_markers: dict[str, object],
    ) -> "AnalysisResult":
        return cls(
            result_id=uuid7(),
            session_id=session_id,
            intercepted_apis=tuple(intercepted_apis),
            websocket_endpoints=tuple(websocket_endpoints),
            spa_routes=tuple(spa_routes),
            framework_fingerprints=tuple(framework_fingerprints),
            dom_snapshot=dom_snapshot,
            hydration_markers=hydration_markers,
            created_at=datetime.now(UTC),
        )
