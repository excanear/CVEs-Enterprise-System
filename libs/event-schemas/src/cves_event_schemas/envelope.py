"""Domain event envelope — canonical, immutable wrapper for all events.

Every event published to Kafka is wrapped in this envelope. Consumers
never inspect the payload without first validating the envelope.

Design constraints:
- All fields are immutable (model_config frozen=True).
- event_id and timestamp are set at construction and never changed.
- correlation_id is propagated from the triggering context (never generated
  inside the envelope itself — callers supply it).
- causation_id points to the event_id of the cause; None for origin events.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cves_db.types import uuid7


def _now_ms() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp() * 1000)


class DomainEventEnvelope(BaseModel):
    """Canonical CloudEvent-compatible envelope for all domain events.

    Consumers must treat instances as read-only. Mutation after construction
    violates the immutability contract of the event log.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    # ── Identity ──────────────────────────────────────────────────────────
    event_id: uuid.UUID = Field(
        default_factory=uuid7,
        description="UUID v7 — globally unique, time-ordered. Immutable.",
    )
    event_type: str = Field(
        description="Dot-separated type string, e.g. 'asi.asset.discovered'.",
        pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$",
    )
    schema_version: str = Field(
        default="1.0.0",
        description="Semver of the Avro schema registered in Schema Registry.",
        pattern=r"^\d+\.\d+\.\d+$",
    )

    # ── Aggregate context ─────────────────────────────────────────────────
    aggregate_id: uuid.UUID = Field(
        description="ID of the aggregate root that emitted this event.",
    )
    aggregate_type: str = Field(
        description="Aggregate class name, e.g. 'Asset'.",
    )
    tenant_id: uuid.UUID = Field(
        description="Owning tenant. Present in every event without exception.",
    )

    # ── Causality ─────────────────────────────────────────────────────────
    correlation_id: uuid.UUID = Field(
        description=(
            "Propagated unchanged across all events in a causal chain. "
            "Use the same correlation_id as the triggering event."
        ),
    )
    causation_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "event_id of the event that directly caused this one. "
            "NULL for origin events (e.g., first event from an external feed)."
        ),
    )

    # ── Timing & source ───────────────────────────────────────────────────
    timestamp: int = Field(
        default_factory=_now_ms,
        description="Unix epoch milliseconds (UTC). Immutable after construction.",
    )
    producer_svc: str = Field(
        description="Name of the service that produced this event, e.g. 'asi-discovery-service'.",
    )

    # ── Payload ───────────────────────────────────────────────────────────
    payload: dict[str, Any] = Field(
        description="Event-specific data. Schema defined per event_type in sub-packages.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Arbitrary string key-value pairs for cross-cutting concerns: "
            "scan_id, workflow_id, retry_count, otel trace headers, etc."
        ),
    )

    # ── Validators ────────────────────────────────────────────────────────

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        if len(v) > 256:
            raise ValueError("event_type must be ≤ 256 characters.")
        return v

    @field_validator("producer_svc")
    @classmethod
    def _validate_producer_svc(cls, v: str) -> str:
        if not v or len(v) > 128:
            raise ValueError("producer_svc must be 1–128 characters.")
        return v

    # ── Helpers ───────────────────────────────────────────────────────────

    def caused_event(
        self,
        *,
        event_type: str,
        aggregate_id: uuid.UUID,
        aggregate_type: str,
        producer_svc: str,
        payload: dict[str, Any],
        schema_version: str = "1.0.0",
        extra_metadata: dict[str, str] | None = None,
    ) -> "DomainEventEnvelope":
        """Construct a new event causally linked to this one.

        The new event inherits correlation_id and sets causation_id = self.event_id.
        tenant_id is also inherited.
        """
        return DomainEventEnvelope(
            event_type=event_type,
            schema_version=schema_version,
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            tenant_id=self.tenant_id,
            correlation_id=self.correlation_id,
            causation_id=self.event_id,
            producer_svc=producer_svc,
            payload=payload,
            metadata={**self.metadata, **(extra_metadata or {})},
        )

    @property
    def timestamp_dt(self) -> datetime:
        """Return timestamp as an aware datetime (UTC)."""
        return datetime.fromtimestamp(self.timestamp / 1000, tz=timezone.utc)

    def to_kafka_headers(self) -> dict[str, str]:
        """Return headers dict suitable for Kafka message headers."""
        headers = {
            "event_type": self.event_type,
            "schema_version": self.schema_version,
            "correlation_id": str(self.correlation_id),
            "tenant_id": str(self.tenant_id),
        }
        if self.causation_id:
            headers["causation_id"] = str(self.causation_id)
        # OTel trace context injected separately by cves_kafka.tracing
        return headers
