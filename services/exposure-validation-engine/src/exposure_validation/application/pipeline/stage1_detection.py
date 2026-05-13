"""Stage 1 — Detection: routes upstream Kafka events to ExposureCandidates.

Maps event_type → ExposureType and extracts relevant fields from the envelope payload.
Returns None for events that carry no actionable signal.
"""
from __future__ import annotations

from typing import Any

import structlog

from cves_event_schemas.envelope import DomainEventEnvelope
from cves_event_schemas.eve.eve_events import ExposureType

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate

log = structlog.get_logger(__name__)

# event_type prefix → (ExposureType, endpoint_path_key, param_key)
_ROUTING_TABLE: dict[str, ExposureType] = {
    "jsi.js.routes_discovered": ExposureType.EXPOSED_ROUTE,
    "jsi.js.bundle_analyzed": ExposureType.PATH_TRAVERSAL,
    "rf.runtime.api_intercepted": ExposureType.EXPOSED_API,
    "rf.runtime.websocket_discovered": ExposureType.WEBSOCKET_UNPROTECTED,
    "asi.asset.discovered": ExposureType.EXPOSED_API,
}


def _extract_candidate(
    event_type: str,
    payload: dict[str, Any],
    tenant_id: str,
) -> ExposureCandidate | None:
    """Extract an ExposureCandidate from a payload, or None if not actionable."""

    exposure_type = _ROUTING_TABLE.get(event_type)
    if exposure_type is None:
        return None

    target_url: str = payload.get("target_url") or payload.get("bundle_url") or payload.get("ws_url", "")
    if not target_url:
        return None

    # jsi.js.bundle_analyzed: only actionable when source map is present (path traversal risk)
    if event_type == "jsi.js.bundle_analyzed":
        if not payload.get("has_source_map"):
            return None

    # rf.runtime.api_intercepted: extract endpoint
    endpoint_path = (
        payload.get("endpoint_url")
        or payload.get("ws_url")
        or ""
    )
    method = payload.get("method", "GET")
    param_names = tuple(payload.get("param_names") or [])

    confidence_hint = _compute_hint(event_type, payload)

    return ExposureCandidate(
        tenant_id=tenant_id,
        target_url=target_url,
        exposure_type=exposure_type,
        signal_source=event_type,
        endpoint_path=endpoint_path,
        method=method,
        param_names=param_names,
        confidence_hint=confidence_hint,
        raw_signals=(payload,),
    )


def _compute_hint(event_type: str, payload: dict[str, Any]) -> float:
    """Initial confidence hint from signal metadata."""
    if event_type == "rf.runtime.api_intercepted":
        # Unauthenticated API call — higher initial confidence
        return 0.65
    if event_type == "rf.runtime.websocket_discovered":
        return 0.60
    if event_type == "jsi.js.routes_discovered":
        # Confidence proportional to number of routes found
        routes = payload.get("total_routes", 0)
        return min(0.40 + routes * 0.02, 0.80)
    if event_type == "jsi.js.bundle_analyzed":
        # Source map exposed = path traversal risk
        return 0.55
    return 0.40  # asi.asset.discovered fallback


class DetectionStage:
    @staticmethod
    def process(envelope: DomainEventEnvelope) -> ExposureCandidate | None:
        """Route an upstream event to an ExposureCandidate, or discard."""
        tenant_id = str(envelope.tenant_id)
        try:
            return _extract_candidate(envelope.event_type, envelope.payload, tenant_id)
        except Exception as exc:
            log.warning("eve.stage1.error", event_type=envelope.event_type, error=str(exc))
            return None
