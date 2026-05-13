"""RF (Runtime Fingerprinting) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _RFBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class ConfidenceSignalPayload(_RFBase):
    """A single signal contributing to a Technology's confidence score."""

    signal_type: Literal[
        "BANNER", "HEADER", "COOKIE", "ERROR_PAGE",
        "JS_BUNDLE", "PORT_FINGERPRINT", "CERT_SAN"
    ]
    weight: float = Field(ge=0.0, le=1.0)
    raw_value: str


class FingerprintCapturedPayload(_RFBase):
    """Payload for event_type='rf.fingerprint.captured'."""

    tech_id: uuid.UUID
    asset_id: uuid.UUID
    vendor: str
    product: str
    version_raw: str | None = None
    cpe_uri: str | None = None
    tech_category: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_signals: list[ConfidenceSignalPayload] = Field(default_factory=list)
    fingerprint_source: Literal["NETWORK", "WEB", "BOTH"]
    detected_in_scan_id: uuid.UUID | None = None


class TechStackIdentifiedPayload(_RFBase):
    """Payload for event_type='rf.techstack.identified'.

    Emitted when a full tech stack snapshot for an asset is ready.
    """

    asset_id: uuid.UUID
    tech_ids: list[uuid.UUID]
    tech_count: int


class VersionConfirmedPayload(_RFBase):
    """Payload for event_type='rf.version.confirmed'."""

    tech_id: uuid.UUID
    asset_id: uuid.UUID
    version: str
    version_major: int | None = None
    version_minor: int | None = None
    version_patch: int | None = None
    cpe_uri: str
    verified_by_signal: Literal[
        "BANNER", "HEADER", "COOKIE", "ERROR_PAGE",
        "JS_BUNDLE", "PORT_FINGERPRINT", "CERT_SAN"
    ]


class TechnologyBecameStalePayload(_RFBase):
    """Payload for event_type='rf.technology.stale'."""

    tech_id: uuid.UUID
    asset_id: uuid.UUID
    stale_since_ms: int
    reason: str


class TechnologyEOLPayload(_RFBase):
    """Payload for event_type='rf.technology.eol'."""

    tech_id: uuid.UUID
    asset_id: uuid.UUID
    vendor: str
    product: str
    version: str
    eol_date: str  # ISO 8601 date


class RuntimeDetectedPayload(_RFBase):
    """Payload for event_type='rf.runtime.detected'."""

    runtime_id: uuid.UUID
    tech_id: uuid.UUID
    asset_id: uuid.UUID
    runtime_type: Literal["PROCESS", "CONTAINER", "SERVERLESS", "VM"]
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING", "UNKNOWN"]


class PrivilegedContainerDetectedPayload(_RFBase):
    """Payload for event_type='rf.runtime.privileged'.

    Critical security event — always triggers an immediate alert path.
    """

    runtime_id: uuid.UUID
    asset_id: uuid.UUID
    container_id: str
    image: str
    image_digest: str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Runtime Analysis Engine payloads (added by runtime-analysis-engine service)
# ──────────────────────────────────────────────────────────────────────────────


class HydrationAnalysisPayload(_RFBase):
    """Payload for event_type='rf.runtime.hydration_analyzed'.

    Emitted after browser-based SSR hydration analysis of a web asset.
    """

    asset_id: uuid.UUID
    framework: str  # REACT | VUE | ANGULAR | NEXT | NUXT | SVELTE | UNKNOWN
    version_hint: str | None = None
    ssr_detected: bool
    hydration_delta_bytes: int
    has_hydration_mismatch: bool


class WebSocketDiscoveredPayload(_RFBase):
    """Payload for event_type='rf.runtime.websocket_discovered'."""

    asset_id: uuid.UUID
    ws_url: str
    protocols: list[str] = Field(default_factory=list)
    message_count_sampled: int = 0


class SPARouteMapPayload(_RFBase):
    """Payload for event_type='rf.runtime.spa_routes_mapped'."""

    asset_id: uuid.UUID
    routes: list[str]
    total_routes: int
    lazy_chunks_detected: bool


class APIInterceptedPayload(_RFBase):
    """Payload for event_type='rf.runtime.api_intercepted'."""

    asset_id: uuid.UUID
    endpoint_url: str
    method: str
    is_graphql: bool = False
    status_code: int | None = None
    param_names: list[str] = Field(default_factory=list)


RF_FINGERPRINT_TOPIC = "rf.fingerprint.events"

RF_EVENT_TYPES = {
    "fingerprint_captured": "rf.fingerprint.captured",
    "techstack_identified": "rf.techstack.identified",
    "version_confirmed": "rf.version.confirmed",
    "technology_stale": "rf.technology.stale",
    "technology_eol": "rf.technology.eol",
    "runtime_detected": "rf.runtime.detected",
    "runtime_privileged": "rf.runtime.privileged",
    # Runtime Analysis Engine events
    "runtime_hydration_analyzed": "rf.runtime.hydration_analyzed",
    "runtime_websocket_discovered": "rf.runtime.websocket_discovered",
    "runtime_spa_routes_mapped": "rf.runtime.spa_routes_mapped",
    "runtime_api_intercepted": "rf.runtime.api_intercepted",
}
