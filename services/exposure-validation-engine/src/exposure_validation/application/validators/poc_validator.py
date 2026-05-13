"""PoCValidator — safe, non-destructive proof-of-concept probes.

All probes are read-only and safe:
  TIMING        — injects sleep-inducing SQL fragments; detects via response delta
  REFLECTION    — sends a benign img tag (no script); detects unencoded reflection
  CORS_PROBE    — sends a cross-origin header; detects wildcard ACAO response
  HEADER_INJECT — tests for header injection via CRLF in param value

No payloads trigger code execution, write operations, or DNS-OOB callbacks.
"""
from __future__ import annotations

import asyncio
import re

import structlog

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate
from exposure_validation.domain.value_objects.poc_result import PoCResult
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber

log = structlog.get_logger(__name__)

# SQL sleep payloads — read-only, no destructive operations
_SQL_SLEEP_PAYLOADS = [
    "' OR SLEEP(2)-- -",
    "'; WAITFOR DELAY '0:0:2'--",
    "1 AND SLEEP(2)",
]

_TIMING_THRESHOLD_MS = 1800.0  # 1.8 s delta signals likely injection

# Reflection marker — benign img tag, no JS
_REFLECT_MARKER = "<img src=evex>"
_REFLECT_PATTERN = re.compile(rb"<img\s+src=evex>", re.IGNORECASE)

_EVIL_ORIGIN = "https://evil.example.com"


async def _timing_probe(url: str, param: str, prober: HTTPProber) -> PoCResult:
    """Measure response time with a clean baseline vs sleep payload."""
    try:
        baseline = await prober.probe_get(f"{url}{'&' if '?' in url else '?'}{param}=1")
        baseline_ms = baseline.response_time_ms

        total_triggered_ms = 0.0
        for payload in _SQL_SLEEP_PAYLOADS:
            import urllib.parse
            encoded = urllib.parse.quote(payload)
            resp = await prober.probe_get(
                f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
            )
            delta = resp.response_time_ms - baseline_ms
            if delta >= _TIMING_THRESHOLD_MS:
                return PoCResult(
                    probe_type="TIMING",
                    triggered=True,
                    evidence=f"Response delta {delta:.0f}ms with payload: {payload!r}",
                    safe=True,
                )

        return PoCResult(probe_type="TIMING", triggered=False, safe=True)
    except Exception as exc:
        log.debug("eve.poc.timing_error", error=str(exc))
        return PoCResult.no_probe()


async def _reflection_probe(url: str, param: str, prober: HTTPProber) -> PoCResult:
    """Check if a benign marker is reflected without HTML encoding."""
    import urllib.parse
    encoded = urllib.parse.quote(_REFLECT_MARKER)
    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
    try:
        resp = await prober.probe_get(probe_url)
        if _REFLECT_PATTERN.search(resp.body):
            return PoCResult(
                probe_type="REFLECTION",
                triggered=True,
                evidence=f"Unencoded marker reflected via param: {param!r}",
                safe=True,
            )
        return PoCResult(probe_type="REFLECTION", triggered=False, safe=True)
    except Exception as exc:
        log.debug("eve.poc.reflection_error", error=str(exc))
        return PoCResult.no_probe()


async def _cors_probe(url: str, prober: HTTPProber) -> PoCResult:
    """Check if the server echoes a cross-origin request's Origin header."""
    try:
        resp = await prober.probe_get(url, headers={"Origin": _EVIL_ORIGIN})
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if acao == _EVIL_ORIGIN or (acao == "*" and acac):
            return PoCResult(
                probe_type="CORS_PROBE",
                triggered=True,
                evidence=f"ACAO={acao!r}, ACAC={acac}",
                safe=True,
            )
        return PoCResult(probe_type="CORS_PROBE", triggered=False, safe=True)
    except Exception as exc:
        log.debug("eve.poc.cors_error", error=str(exc))
        return PoCResult.no_probe()


async def _header_injection_probe(url: str, param: str, prober: HTTPProber) -> PoCResult:
    """Send CRLF in a param value and check if it appears as a response header."""
    import urllib.parse
    payload = "injected\r\nX-Eve-Injected: detected"
    encoded = urllib.parse.quote(payload)
    probe_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
    try:
        resp = await prober.probe_get(probe_url)
        if "x-eve-injected" in resp.headers:
            return PoCResult(
                probe_type="HEADER_INJECTION",
                triggered=True,
                evidence=f"CRLF injection via param: {param!r}",
                safe=True,
            )
        return PoCResult(probe_type="HEADER_INJECTION", triggered=False, safe=True)
    except Exception as exc:
        log.debug("eve.poc.header_injection_error", error=str(exc))
        return PoCResult.no_probe()


class PoCValidator:
    """Runs all safe PoC probes and returns the first that triggered, or no-trigger."""

    @staticmethod
    async def probe(
        candidate: ExposureCandidate,
        prober: HTTPProber,
    ) -> PoCResult:
        url = candidate.full_url
        param = candidate.param_names[0] if candidate.param_names else "q"

        # CORS probe is independent of param availability
        cors_task = _cors_probe(url, prober)

        if candidate.param_names:
            timing_task = _timing_probe(url, param, prober)
            reflect_task = _reflection_probe(url, param, prober)
            inject_task = _header_injection_probe(url, param, prober)
            results = await asyncio.gather(
                cors_task, timing_task, reflect_task, inject_task
            )
        else:
            results = [await cors_task]

        # Return first triggered result; prefer higher-confidence probe types
        priority = ["TIMING", "HEADER_INJECTION", "REFLECTION", "CORS_PROBE"]
        triggered = [r for r in results if r.triggered]
        triggered.sort(key=lambda r: priority.index(r.probe_type) if r.probe_type in priority else 99)

        return triggered[0] if triggered else PoCResult.no_probe()
