"""One-call FastAPI observability wiring.

Usage::

    from cves_observability.instrumentation import instrument_app

    def create_app() -> FastAPI:
        app = FastAPI(lifespan=lifespan, ...)
        app.include_router(health.router)
        app.include_router(router)
        instrument_app(app, service_name="my-service")
        return app

What ``instrument_app`` does
----------------------------
1. Instruments the app with the OpenTelemetry FastAPI auto-instrumentation
   (``FastAPIInstrumentor``) so every request automatically gets a trace span.
2. Optionally wires ``SQLAlchemyInstrumentor`` if the library is available.
3. Adds :class:`~cves_observability.middleware.PrometheusHTTPMiddleware` to
   record ``http_requests_total`` and ``http_request_duration_seconds``.
4. Adds :class:`~cves_observability.middleware.CorrelationIDMiddleware` as the
   outermost middleware so the correlation ID is available to all inner layers.

The :class:`~cves_observability.metrics.PrometheusMetrics` instance is stored
on ``app.state.metrics`` so routes can access it via ``request.app.state.metrics``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

from cves_observability.metrics import PrometheusMetrics
from cves_observability.middleware import CorrelationIDMiddleware, PrometheusHTTPMiddleware


def instrument_app(
    app: "FastAPI",
    *,
    service_name: str,
    metrics: PrometheusMetrics | None = None,
) -> None:
    """Wire full observability stack into a FastAPI application.

    Parameters
    ----------
    app:
        The FastAPI instance returned by ``FastAPI(...)``.
    service_name:
        Logical service name used as the Prometheus ``service`` label and OTel
        resource attribute. Should match the ``service_name`` passed to
        :func:`~cves_observability.tracing.setup_tracing`.
    metrics:
        An existing :class:`~cves_observability.metrics.PrometheusMetrics`
        instance.  When *None* a new one is created automatically and stored
        on ``app.state.metrics``.
    """
    if metrics is None:
        metrics = PrometheusMetrics(service_name=service_name)

    # Expose on app.state so route handlers can reach counters if needed.
    app.state.metrics = metrics

    # ── 1. OpenTelemetry FastAPI auto-instrumentation ──────────────────────
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: PLC0415

        FastAPIInstrumentor.instrument_app(
            app,
            excluded_urls="health/live,health/ready,health/deps,metrics",
        )
    except Exception:  # noqa: BLE001  (library may not be installed)
        pass

    # ── 2. SQLAlchemy OTel instrumentation (best-effort) ─────────────────
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # noqa: PLC0415

        SQLAlchemyInstrumentor().instrument()
    except Exception:  # noqa: BLE001
        pass

    # ── 3. Prometheus HTTP metrics (inner middleware) ──────────────────────
    # add_middleware wraps in LIFO order: last-added = outermost.
    # PrometheusHTTPMiddleware is added first → innermost → wraps the handler.
    app.add_middleware(PrometheusHTTPMiddleware, metrics=metrics)

    # ── 4. Correlation ID (outer middleware) ──────────────────────────────
    app.add_middleware(CorrelationIDMiddleware)
