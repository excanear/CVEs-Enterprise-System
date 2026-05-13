"""Exposure Validation Engine — domain event schemas.

Topic: eve.exposure.events
All payloads extend _EVEBase (frozen Pydantic model).
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

EVE_EXPOSURE_TOPIC = "eve.exposure.events"

EVE_EVENT_TYPES: dict[str, str] = {
    "candidate_received": "eve.exposure.candidate_received",
    "validation_completed": "eve.exposure.validation_completed",
    "exposure_confirmed": "eve.exposure.confirmed",
}


class ExposureType(str, Enum):
    MISSING_AUTH = "MISSING_AUTH"
    EXPOSED_API = "EXPOSED_API"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    SECURITY_HEADER_MISSING = "SECURITY_HEADER_MISSING"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INJECTION_SURFACE = "INJECTION_SURFACE"
    EXPOSED_ROUTE = "EXPOSED_ROUTE"
    WEBSOCKET_UNPROTECTED = "WEBSOCKET_UNPROTECTED"


class ValidationVerdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class _EVEBase(BaseModel):
    model_config = ConfigDict(frozen=True)


class ExposureCandidateReceivedPayload(_EVEBase):
    job_id: str
    tenant_id: str
    target_url: str
    exposure_type: str
    signal_source: str
    signal_count: int
    initial_confidence: float = Field(ge=0.0, le=1.0)


class ValidationCompletedPayload(_EVEBase):
    job_id: str
    tenant_id: str
    target_url: str
    exposure_type: str
    verdict: str
    final_confidence: float = Field(ge=0.0, le=1.0)
    stages_passed: list[str]
    evidence_count: int
    duration_seconds: float | None = None


class ExposureConfirmedPayload(_EVEBase):
    job_id: str
    tenant_id: str
    target_url: str
    exposure_type: str
    final_confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str
    endpoint_path: str | None = None
    method: str | None = None
    param_names: list[str] = Field(default_factory=list)
    poc_triggered: bool = False
    poc_type: str | None = None
