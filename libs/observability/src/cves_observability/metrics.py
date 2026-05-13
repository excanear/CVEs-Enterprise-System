"""Prometheus metrics registry for all platform services.

Each BC service instantiates PrometheusMetrics with its service_name.
The metrics are registered on the default CollectorRegistry and exposed
at /metrics by the HealthRouter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

_DEFAULT_BUCKETS: Final[tuple[float, ...]] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


@dataclass
class PrometheusMetrics:
    """Standard platform metrics exposed by every service."""

    service_name: str

    # Populated by __post_init__
    http_requests_total: "Counter" = field(init=False)  # type: ignore[type-arg]
    http_request_duration_seconds: "Histogram" = field(init=False)  # type: ignore[type-arg]
    kafka_messages_consumed_total: "Counter" = field(init=False)  # type: ignore[type-arg]
    kafka_messages_published_total: "Counter" = field(init=False)  # type: ignore[type-arg]
    kafka_consumer_errors_total: "Counter" = field(init=False)  # type: ignore[type-arg]
    db_query_duration_seconds: "Histogram" = field(init=False)  # type: ignore[type-arg]
    domain_events_emitted_total: "Counter" = field(init=False)  # type: ignore[type-arg]

    def __post_init__(self) -> None:
        try:
            from prometheus_client import Counter, Histogram

            svc = self.service_name

            self.http_requests_total = Counter(
                f"{svc}_http_requests_total",
                "Total HTTP requests",
                ["method", "path", "status_code"],
            )
            self.http_request_duration_seconds = Histogram(
                f"{svc}_http_request_duration_seconds",
                "HTTP request duration",
                ["method", "path"],
                buckets=_DEFAULT_BUCKETS,
            )
            self.kafka_messages_consumed_total = Counter(
                f"{svc}_kafka_messages_consumed_total",
                "Total Kafka messages consumed",
                ["topic", "event_type"],
            )
            self.kafka_messages_published_total = Counter(
                f"{svc}_kafka_messages_published_total",
                "Total Kafka messages published",
                ["topic", "event_type"],
            )
            self.kafka_consumer_errors_total = Counter(
                f"{svc}_kafka_consumer_errors_total",
                "Total Kafka consumer errors",
                ["topic", "error_type"],
            )
            self.db_query_duration_seconds = Histogram(
                f"{svc}_db_query_duration_seconds",
                "DB query duration",
                ["operation"],
                buckets=_DEFAULT_BUCKETS,
            )
            self.domain_events_emitted_total = Counter(
                f"{svc}_domain_events_emitted_total",
                "Total domain events emitted",
                ["event_type"],
            )
        except ImportError:
            raise RuntimeError("prometheus-client is required. Install cves-observability.")
