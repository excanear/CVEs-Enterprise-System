"""OTel SDK bootstrapper for all platform services.

Call setup_tracing() once at service startup, before any other code
that might generate spans. The function is idempotent — calling it
multiple times in tests is safe (subsequent calls are no-ops).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_configured = False


def setup_tracing(
    *,
    service_name: str,
    service_version: str = "0.0.0",
    otlp_endpoint: str = "http://otel-collector:4317",
    environment: str = "production",
) -> None:
    """Initialise the OTel SDK with OTLP gRPC exporter.

    Parameters
    ----------
    service_name:
        Injected into every span as service.name resource attribute.
    service_version:
        Injected as service.version.
    otlp_endpoint:
        gRPC endpoint for the OTLP exporter.
    environment:
        deployment.environment attribute (production / staging / …).
    """
    global _configured
    if _configured:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": service_name,
                "service.version": service_version,
                "deployment.environment": environment,
            }
        )
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _configured = True
        logger.info("otel_tracing_configured", extra={"service": service_name})
    except ImportError:
        logger.warning("opentelemetry-sdk not installed — tracing disabled.")


def get_tracer(name: str) -> "trace.Tracer":  # type: ignore[name-defined]
    """Return a tracer for the given instrumentation scope name."""
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except ImportError:
        raise RuntimeError("opentelemetry-sdk is required. Install cves-observability.")
