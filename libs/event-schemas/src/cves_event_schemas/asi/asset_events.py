"""ASI (Attack Surface Intelligence) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _ASIBase(BaseModel):
    model_config = ConfigDict(frozen=True)


# ── Asset Events ──────────────────────────────────────────────────────────────

class AssetDiscoveredPayload(_ASIBase):
    """Payload for event_type='asi.asset.discovered'."""

    asset_id: uuid.UUID
    asset_type: Literal["HOST", "DOMAIN", "CLOUD_RESOURCE", "URL", "SERVICE"]
    discovery_source: Literal["MANUAL", "PASSIVE_DNS", "ACTIVE_SCAN", "CLOUD_API", "CIDR_SWEEP"]
    ip_address: str | None = None
    fqdn: str | None = None
    cloud_resource_id: str | None = None
    cloud_provider: Literal["AWS", "GCP", "AZURE"] | None = None
    scan_id: uuid.UUID | None = None


class AssetScopedPayload(_ASIBase):
    """Payload for event_type='asi.asset.scoped'."""

    asset_id: uuid.UUID
    in_scope: bool
    scope_group: str
    rationale: str


class AssetActivatedPayload(_ASIBase):
    """Payload for event_type='asi.asset.activated'."""

    asset_id: uuid.UUID
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING", "UNKNOWN"]
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AssetRiskContextUpdatedPayload(_ASIBase):
    """Payload for event_type='asi.asset.risk_context_updated'."""

    asset_id: uuid.UUID
    old_criticality: str
    new_criticality: str
    owner: str | None = None
    environment: str | None = None


class AssetDecommissionedPayload(_ASIBase):
    """Payload for event_type='asi.asset.decommissioned'."""

    asset_id: uuid.UUID
    reason: str
    decommissioned_by: str


class AssetExcludedPayload(_ASIBase):
    """Payload for event_type='asi.asset.excluded'."""

    asset_id: uuid.UUID
    rationale: str
    excluded_by: str


# ── Host Events ───────────────────────────────────────────────────────────────

class HostPortStateChangedPayload(_ASIBase):
    """Payload for event_type='asi.host.port_state_changed'."""

    asset_id: uuid.UUID
    port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP"]
    old_state: Literal["OPEN", "FILTERED", "CLOSED", "UNKNOWN"]
    new_state: Literal["OPEN", "FILTERED", "CLOSED", "UNKNOWN"]
    service_name: str | None = None
    banner: str | None = None
    detected_by_scan_id: uuid.UUID


class HostStatusChangedPayload(_ASIBase):
    """Payload for event_type='asi.host.status_changed'."""

    asset_id: uuid.UUID
    old_status: Literal["ONLINE", "OFFLINE", "UNREACHABLE", "UNKNOWN"]
    new_status: Literal["ONLINE", "OFFLINE", "UNREACHABLE", "UNKNOWN"]


class HostOSIdentifiedPayload(_ASIBase):
    """Payload for event_type='asi.host.os_identified'."""

    asset_id: uuid.UUID
    os_family: str
    os_version: str
    confidence: float = Field(ge=0.0, le=1.0)


# ── Domain Events ─────────────────────────────────────────────────────────────

class DomainDanglingDetectedPayload(_ASIBase):
    """Payload for event_type='asi.domain.dangling_detected'."""

    asset_id: uuid.UUID
    fqdn: str
    dangling_ip: str
    takeover_risk_score: float = Field(ge=0.0, le=1.0)


class DomainResolutionChangedPayload(_ASIBase):
    """Payload for event_type='asi.domain.resolution_changed'."""

    asset_id: uuid.UUID
    fqdn: str
    old_ips: list[str]
    new_ips: list[str]
    dns_status: str


class CertificateExpiringSoonPayload(_ASIBase):
    """Payload for event_type='asi.domain.certificate_expiring'."""

    asset_id: uuid.UUID
    fqdn: str
    days_to_expiry: int
    fingerprint_sha256: str


# ── Scan Events ───────────────────────────────────────────────────────────────

class ScanStartedPayload(_ASIBase):
    """Payload for event_type='asi.scan.started'."""

    scan_id: uuid.UUID
    scan_type: str
    target_count: int
    initiated_by: str


class ScanCompletedPayload(_ASIBase):
    """Payload for event_type='asi.scan.completed'."""

    scan_id: uuid.UUID
    scan_type: str
    total_targets: int
    discovered: int
    updated: int
    errors: int
    duration_seconds: float
    discovered_asset_ids: list[uuid.UUID]
    updated_asset_ids: list[uuid.UUID]


class ScanFailedPayload(_ASIBase):
    """Payload for event_type='asi.scan.failed'."""

    scan_id: uuid.UUID
    error_code: str
    error_message: str
    retryable: bool


# ── Topic constants ───────────────────────────────────────────────────────────

ASI_ASSET_TOPIC = "asi.asset.events"

ASI_EVENT_TYPES = {
    "discovered": "asi.asset.discovered",
    "scoped": "asi.asset.scoped",
    "activated": "asi.asset.activated",
    "risk_context_updated": "asi.asset.risk_context_updated",
    "decommissioned": "asi.asset.decommissioned",
    "excluded": "asi.asset.excluded",
    "port_state_changed": "asi.host.port_state_changed",
    "host_status_changed": "asi.host.status_changed",
    "os_identified": "asi.host.os_identified",
    "domain_dangling": "asi.domain.dangling_detected",
    "domain_resolution_changed": "asi.domain.resolution_changed",
    "certificate_expiring": "asi.domain.certificate_expiring",
    "scan_started": "asi.scan.started",
    "scan_completed": "asi.scan.completed",
    "scan_failed": "asi.scan.failed",
}
