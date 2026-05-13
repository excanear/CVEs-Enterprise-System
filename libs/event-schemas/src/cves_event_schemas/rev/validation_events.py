"""REV (Runtime Exposure Validation) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _REVBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class ConfidenceScorePayload(_REVBase):
    """Multi-signal confidence breakdown."""

    overall: float = Field(ge=0.0, le=1.0)
    version_match: float = Field(ge=0.0, le=1.0, description="Weight 0.35")
    network_reachable: float = Field(ge=0.0, le=1.0, description="Weight 0.30")
    poc_evidence: float = Field(ge=0.0, le=1.0, description="Weight 0.25")
    no_compensating_control: float = Field(ge=0.0, le=1.0, description="Weight 0.10")


class ExposureCandidateCreatedPayload(_REVBase):
    """Payload for event_type='rev.exposure.candidate_created'."""

    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    tech_id: uuid.UUID
    cpe_uri: str | None = None
    triggered_by: Literal["AUTOMATIC", "MANUAL", "FEED_UPDATE", "SCAN_UPDATE"] = "AUTOMATIC"


class ValidationStartedPayload(_REVBase):
    """Payload for event_type='rev.validation.started'."""

    exposure_id: uuid.UUID
    validation_id: uuid.UUID
    workflow_id: uuid.UUID
    gate_threshold: float = Field(ge=0.0, le=1.0)
    triggered_by: str


class ValidationStepCompletedPayload(_REVBase):
    """Payload for event_type='rev.validation.step_completed'."""

    exposure_id: uuid.UUID
    validation_id: uuid.UUID
    step_name: Literal["DISCOVER", "FINGERPRINT", "REACHABILITY", "EXPLOIT", "CONFIDENCE", "GATE"]
    result: Literal["PASS", "FAIL", "SKIP"]
    confidence_delta: float | None = None
    evidence_id: uuid.UUID | None = None
    failure_reason: str | None = None
    duration_ms: int | None = None


class ValidationGateDecidedPayload(_REVBase):
    """Payload for event_type='rev.validation.gate_decided'."""

    exposure_id: uuid.UUID
    validation_id: uuid.UUID
    gate_decision: Literal["APPROVED", "REJECTED"]
    final_confidence: float = Field(ge=0.0, le=1.0)
    gate_threshold: float = Field(ge=0.0, le=1.0)
    confidence_breakdown: ConfidenceScorePayload


class ExposureConfirmedPayload(_REVBase):
    """Payload for event_type='rev.exposure.confirmed'."""

    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    tech_id: uuid.UUID
    confidence_overall: float = Field(ge=0.0, le=1.0)
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    confidence_breakdown: ConfidenceScorePayload
    evidence_ids: list[uuid.UUID] = Field(default_factory=list)


class ExposureRefutedPayload(_REVBase):
    """Payload for event_type='rev.exposure.refuted'."""

    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    refutation_signal: str
    evidence_id: uuid.UUID | None = None


class FalsePositiveMarkedPayload(_REVBase):
    """Payload for event_type='rev.exposure.false_positive'."""

    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    classification_reason: Literal[
        "VERSION_NOT_AFFECTED", "COMPENSATING_CONTROL",
        "NETWORK_ISOLATED", "VENDOR_PATCH_APPLIED", "MANUAL_REVIEW"
    ]
    classified_by: str


class ExposureResolvedPayload(_REVBase):
    """Payload for event_type='rev.exposure.resolved'."""

    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    resolution_type: Literal["PATCHED", "DECOMMISSIONED", "ACCEPTED", "MITIGATED"]
    resolved_by: str


class EvidenceCollectedPayload(_REVBase):
    """Payload for event_type='rev.evidence.collected'."""

    evidence_id: uuid.UUID
    exposure_id: uuid.UUID
    evidence_type: Literal[
        "NETWORK_REACHABLE", "NETWORK_UNREACHABLE",
        "VERSION_MATCH", "VERSION_MISMATCH",
        "POC_SUCCEEDED", "POC_FAILED",
        "COMPENSATING_CONTROL", "BANNER_MATCH",
        "CERT_MATCH", "MANUAL_OVERRIDE"
    ]
    signal_weight: float = Field(ge=0.0, le=1.0)
    artifact_type: str
    artifact_hash_sha256: str
    collected_by: str
    ttl_expires_at_ms: int


REV_VALIDATION_TOPIC = "rev.validation.events"

REV_EVENT_TYPES = {
    "candidate_created": "rev.exposure.candidate_created",
    "validation_started": "rev.validation.started",
    "step_completed": "rev.validation.step_completed",
    "gate_decided": "rev.validation.gate_decided",
    "confirmed": "rev.exposure.confirmed",
    "refuted": "rev.exposure.refuted",
    "false_positive": "rev.exposure.false_positive",
    "resolved": "rev.exposure.resolved",
    "suppressed": "rev.exposure.suppressed",
    "expired": "rev.exposure.expired",
    "evidence_collected": "rev.evidence.collected",
}
