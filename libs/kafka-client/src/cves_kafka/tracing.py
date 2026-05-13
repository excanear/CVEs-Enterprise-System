"""OTel W3C Trace Context injection/extraction for Kafka headers.

Kafka headers use string keys and string values.
The W3C traceparent header (https://www.w3.org/TR/trace-context/) carries
trace-id, parent-id, and trace-flags — enabling end-to-end correlation across
HTTP → Kafka → HTTP hops without relying on application-level metadata.

Gracefully degrades to a no-op if opentelemetry-sdk is not installed.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from opentelemetry import context, propagate
    from opentelemetry.propagators.textmap import Setter, Getter

    _OTEL_AVAILABLE = True

    class _DictSetter(Setter):
        def set(self, carrier: dict[str, str], key: str, value: str) -> None:
            carrier[key] = value

    class _DictGetter(Getter):
        def get(self, carrier: dict[str, str], key: str) -> list[str] | None:
            v = carrier.get(key)
            return [v] if v else None

        def keys(self, carrier: dict[str, str]) -> list[str]:
            return list(carrier.keys())

    _SETTER = _DictSetter()
    _GETTER = _DictGetter()

except ImportError:
    _OTEL_AVAILABLE = False
    _SETTER = None  # type: ignore[assignment]
    _GETTER = None  # type: ignore[assignment]


def inject_trace_context(headers: dict[str, str]) -> None:
    """Inject the active OTel span context into the Kafka headers dict."""
    if not _OTEL_AVAILABLE:
        return
    try:
        propagate.inject(headers, setter=_SETTER)
    except Exception as exc:  # noqa: BLE001
        logger.debug("otel_inject_failed: %s", exc)


def extract_trace_context(headers: dict[str, str]) -> Any:
    """Extract OTel trace context from Kafka headers and activate it.

    Returns the context token — caller should detach it when processing ends
    (optional, Kafka consumer coroutines are short-lived).
    """
    if not _OTEL_AVAILABLE:
        return None
    try:
        ctx = propagate.extract(headers, getter=_GETTER)
        return context.attach(ctx)
    except Exception as exc:  # noqa: BLE001
        logger.debug("otel_extract_failed: %s", exc)
        return None
