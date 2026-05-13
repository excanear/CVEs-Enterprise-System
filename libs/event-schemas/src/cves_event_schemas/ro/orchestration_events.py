"""RO (Risk Orchestration) domain event payloads."""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _ROBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class SagaInitiatedPayload(_ROBase):
    """Payload for event_type='ro.saga.validation_initiated'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    steps: list[str] = Field(
        default=["DISCOVER", "FINGERPRINT", "REACHABILITY", "EXPLOIT", "CONFIDENCE", "GATE"],
        description="Ordered list of saga steps.",
    )
    timeout_at_ms: int


class SagaStepRequestedPayload(_ROBase):
    """Payload for event_type='ro.saga.step_requested'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    step_name: str
    step_index: int
    input_refs: dict[str, str] = Field(default_factory=dict)


class SagaCompensateRequestedPayload(_ROBase):
    """Payload for event_type='ro.saga.compensate_requested'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    failed_step: str
    failure_reason: str
    compensation_steps: list[str]


class SagaCompletedPayload(_ROBase):
    """Payload for event_type='ro.saga.completed'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    final_status: Literal["CONFIRMED", "REFUTED", "FALSE_POSITIVE"]
    duration_ms: int


class SagaCompensatedPayload(_ROBase):
    """Payload for event_type='ro.saga.compensated'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    compensated_steps: list[str]
    final_exposure_status: str


class WorkflowTimeoutPayload(_ROBase):
    """Payload for event_type='ro.workflow.timeout'."""

    workflow_id: uuid.UUID
    exposure_id: uuid.UUID
    elapsed_seconds: float
    current_step: str


class RiskScoreUpdatedPayload(_ROBase):
    """Payload for event_type='ro.risk_score.updated'."""

    asset_id: uuid.UUID
    old_score: float | None
    new_score: float = Field(ge=0.0, le=10.0)
    exposure_count: int
    critical_count: int
    high_count: int
    attack_path_count: int
    blast_radius: int


class AlertCreatedPayload(_ROBase):
    """Payload for event_type='ro.alert.created'."""

    alert_id: uuid.UUID
    exposure_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    title: str
    dedup_key: str
    kev_listed: bool = False


class AlertEscalatedPayload(_ROBase):
    """Payload for event_type='ro.alert.escalated'."""

    alert_id: uuid.UUID
    old_severity: str
    new_severity: str
    reason: str


RO_ORCHESTRATION_TOPIC = "ro.orchestration.events"
RO_ALERTS_TOPIC = "ro.alerts.events"

RO_EVENT_TYPES = {
    "saga_initiated": "ro.saga.validation_initiated",
    "step_requested": "ro.saga.step_requested",
    "compensate_requested": "ro.saga.compensate_requested",
    "saga_completed": "ro.saga.completed",
    "saga_compensated": "ro.saga.compensated",
    "workflow_timeout": "ro.workflow.timeout",
    "risk_score_updated": "ro.risk_score.updated",
    "alert_created": "ro.alert.created",
    "alert_acknowledged": "ro.alert.acknowledged",
    "alert_suppressed": "ro.alert.suppressed",
    "alert_escalated": "ro.alert.escalated",
}
