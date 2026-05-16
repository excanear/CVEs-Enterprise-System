"""ASGI middlewares for observability.

Provides:
  - CorrelationIDMiddleware  — extracts or generates X-Correlation-ID, binds
    it to structlog context vars and the current OTel span.
  - PrometheusHTTPMiddleware — records HTTP request count and latency into a
    PrometheusMetrics instance stored on app.state.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    from cves_observability.metrics import PrometheusMetrics

from cves_observability.logging import bind_correlation, bind_tenant, clear_log_context

# ── Path normalisation ─────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_INT_SEGMENT_RE = re.compile(r"/\d+")


def _normalize_path(path: str) -> str:
    """Replace UUID and integer path segments with ``{id}`` to cap cardinality."""
    path = _UUID_RE.sub("{id}", path)
    path = _INT_SEGMENT_RE.sub("/{id}", path)
    return path


# ── Correlation ID middleware ──────────────────────────────────────────────────

class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Extract or generate ``X-Correlation-ID`` for every HTTP request.

    * Reads the header from the incoming request (useful when called by an
      upstream gateway that already assigned a correlation ID).
    * Falls back to a freshly generated UUID4.
    * Binds the value into structlog context-vars so all log lines emitted
      during the request carry ``correlation_id``.
    * Adds the same value as an attribute on the current OTel span.
    * Echoes the correlation ID in the response header so callers can
      correlate client-side logs.
    * Also reads ``X-Tenant-ID`` and binds it to structlog.
    * Calls :func:`clear_log_context` after the response to prevent context
      leakage into subsequent requests on the same async task.
    """

    CORRELATION_HEADER: str = "X-Correlation-ID"
    TENANT_HEADER: str = "X-Tenant-ID"

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        correlation_id: str = (
            request.headers.get(self.CORRELATION_HEADER) or str(uuid.uuid4())
        )
        tenant_id: str = request.headers.get(self.TENANT_HEADER, "")

        # Bind to structlog context vars (cleared after response)
        bind_correlation(correlation_id)
        if tenant_id:
            bind_tenant(tenant_id)

        # Propagate into the active OTel span (best-effort)
        try:
            from opentelemetry import trace  # noqa: PLC0415

            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute("correlation.id", correlation_id)
                if tenant_id:
                    span.set_attribute("tenant.id", tenant_id)
        except Exception:  # noqa: BLE001
            pass

        try:
            response = await call_next(request)
        finally:
            clear_log_context()

        response.headers[self.CORRELATION_HEADER] = correlation_id
        return response


# ── Prometheus HTTP metrics middleware ─────────────────────────────────────────

class PrometheusHTTPMiddleware(BaseHTTPMiddleware):
    """Record HTTP request count and duration into a :class:`PrometheusMetrics`.

    Path segments that look like UUIDs or plain integers are normalised to
    ``{id}`` to avoid cardinality explosion in the ``path`` label.
    """

    def __init__(self, app, *, metrics: "PrometheusMetrics") -> None:
        super().__init__(app)
        self._metrics = metrics

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        method = request.method
        path = _normalize_path(request.url.path)

        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        self._metrics.http_requests_total.labels(
            method=method,
            path=path,
            status_code=str(response.status_code),
        ).inc()
        self._metrics.http_request_duration_seconds.labels(
            method=method,
            path=path,
        ).observe(duration)

        return response
