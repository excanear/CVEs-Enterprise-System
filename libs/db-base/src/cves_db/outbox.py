"""Transactional Outbox pattern implementation.

Every BC that publishes domain events uses an outbox table in its own
PostgreSQL schema. The OutboxPoller reads unpublished rows and publishes
them to Kafka inside a Kafka transaction, then marks them as published.

This guarantees exactly-once delivery without a distributed 2PC.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base_model import Base


class OutboxEntry(Base):
    """Concrete outbox table.

    Each BC schema declares its own outbox by subclassing this model and
    setting __tablename__ and __table_args__ appropriately.

    Example::

        class ASIOutboxEntry(OutboxEntry):
            __tablename__ = "outbox"
            __table_args__ = {"schema": "asi"}
    """

    __abstract__ = True

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
        doc="Monotonic sequence used for ordered polling.",
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        doc="Globally unique event identifier (UUID v7). Also used for consumer dedup.",
    )
    event_type: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        doc="Dot-separated event type, e.g. 'asi.asset.discovered'.",
    )
    aggregate_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        doc="ID of the aggregate root that emitted the event.",
    )
    aggregate_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Aggregate class name, e.g. 'Asset'.",
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        doc="Owning tenant.",
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        doc="Correlation chain ID propagated across all causally related events.",
    )
    causation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        doc="event_id of the event that caused this one. NULL for origin events.",
    )
    kafka_topic: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        doc="Target Kafka topic.",
    )
    kafka_key: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        doc="Kafka message key used for partitioning.",
    )
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        doc="Event payload. Serialized as JSON; the Kafka producer converts to Avro.",
    )
    headers: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
        server_default="{}",
        doc="Kafka headers to attach (OTel trace context, schema version, etc.).",
    )
    schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default="1.0.0",
        doc="Avro schema version string (semver).",
    )
    published: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
        index=True,
        doc="Set to TRUE by the OutboxPoller after successful Kafka delivery.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    retry_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        server_default="0",
        doc="Number of failed publish attempts.",
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Last error message from a failed publish attempt.",
    )


class OutboxMixin:
    """Domain-layer mixin providing outbox-append helpers.

    Aggregates that need to publish events mix this in and call
    `self._append_event(...)`. The Unit-of-Work flushes collected entries
    to the BC's outbox table within the same transaction.
    """

    def __init__(self) -> None:
        self._pending_events: list[dict[str, Any]] = []

    def _append_event(
        self,
        *,
        event_id: uuid.UUID,
        event_type: str,
        aggregate_id: uuid.UUID,
        aggregate_type: str,
        tenant_id: uuid.UUID,
        correlation_id: uuid.UUID,
        kafka_topic: str,
        kafka_key: str,
        payload: dict[str, Any],
        causation_id: uuid.UUID | None = None,
        schema_version: str = "1.0.0",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Stage a domain event for outbox persistence."""
        self._pending_events.append(
            {
                "event_id": event_id,
                "event_type": event_type,
                "aggregate_id": aggregate_id,
                "aggregate_type": aggregate_type,
                "tenant_id": tenant_id,
                "correlation_id": correlation_id,
                "causation_id": causation_id,
                "kafka_topic": kafka_topic,
                "kafka_key": str(kafka_key),
                "payload": payload,
                "schema_version": schema_version,
                "headers": headers or {},
                "published": False,
            }
        )

    def collect_events(self) -> list[dict[str, Any]]:
        """Return and clear pending events. Called by the Unit-of-Work."""
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
