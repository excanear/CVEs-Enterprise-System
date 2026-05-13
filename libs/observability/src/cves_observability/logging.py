"""Structured JSON logging via structlog.

Call setup_logging() once at startup (before the first log call).
All subsequent logging.getLogger() calls will emit JSON lines with
trace_id, span_id, tenant_id automatically bound from the OTel context.
"""
from __future__ import annotations

import logging
import sys
from typing import Any


def _add_otel_context(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor: inject OTel trace_id + span_id when available."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            event_dict["trace_id"] = format(ctx.trace_id, "032x")
            event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:  # noqa: BLE001
        pass
    return event_dict


def setup_logging(
    *,
    log_level: str = "INFO",
    service_name: str = "unknown",
    pretty: bool = False,
) -> None:
    """Configure structlog + stdlib logging for JSON output.

    Parameters
    ----------
    log_level:
        Root log level string, e.g. "DEBUG", "INFO", "WARNING".
    service_name:
        Added as a static field to every log record.
    pretty:
        If True, use ConsoleRenderer for human-readable local dev output.
    """
    import structlog

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        _add_otel_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if pretty:
        renderer: Any = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level.upper())

    logging.getLogger("uvicorn.access").propagate = True
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def bind_tenant(tenant_id: str) -> None:
    """Bind tenant_id to the structlog context var (per async task)."""
    import structlog

    structlog.contextvars.bind_contextvars(tenant_id=tenant_id)


def bind_correlation(correlation_id: str) -> None:
    """Bind correlation_id to the structlog context var (per async task)."""
    import structlog

    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)


def clear_log_context() -> None:
    """Clear all structlog context vars — call after each request ends."""
    import structlog

    structlog.contextvars.clear_contextvars()
