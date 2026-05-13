"""cves_observability — OTel tracing, structlog JSON logging, Prometheus metrics, health checks."""

from .tracing import setup_tracing, get_tracer
from .logging import setup_logging, bind_tenant, bind_correlation, clear_log_context
from .metrics import PrometheusMetrics
from .health import HealthRouter

__all__ = [
    "setup_tracing",
    "get_tracer",
    "setup_logging",
    "bind_tenant",
    "bind_correlation",
    "clear_log_context",
    "PrometheusMetrics",
    "HealthRouter",
]
