"""ParserValidator — analyzes response body for information disclosure risks.

Detects:
  - Stack traces (Java, Python, Node.js, PHP patterns)
  - JSON error leaks
  - Debug page signatures (Django, Whoops, Spring Boot)
  - Input reflection (sends a UUID marker and checks if it appears in the response)
"""
from __future__ import annotations

import re
import uuid

import structlog

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate
from exposure_validation.domain.value_objects.parser_findings import ParserFindings
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber

log = structlog.get_logger(__name__)

# Stack trace regex patterns — order matters (most specific first)
_STACK_TRACE_PATTERNS = [
    re.compile(rb"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(rb"at [A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$]*\(", re.MULTILINE),
    re.compile(rb"Exception in thread", re.IGNORECASE),
    re.compile(rb"java\.lang\.[A-Za-z]+Exception", re.IGNORECASE),
    re.compile(rb"ReferenceError:|TypeError:|SyntaxError:", re.IGNORECASE),
    re.compile(rb"Fatal error:.*on line \d+", re.IGNORECASE),
]

_JSON_ERROR_PATTERNS = [
    re.compile(rb'"error"\s*:', re.IGNORECASE),
    re.compile(rb'"stack"\s*:', re.IGNORECASE),
    re.compile(rb'"trace"\s*:', re.IGNORECASE),
    re.compile(rb'"exception"\s*:', re.IGNORECASE),
]

_DEBUG_PATTERNS = [
    re.compile(rb"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(rb"X-Debug-Token", re.IGNORECASE),
    re.compile(rb"Whoops!.*<title>", re.IGNORECASE),
    re.compile(rb"<title>.*Django.*DEBUG.*</title>", re.IGNORECASE),
    re.compile(rb"Spring Boot.*Whitelabel Error Page", re.IGNORECASE),
]


class ParserValidator:
    @staticmethod
    async def analyze(
        candidate: ExposureCandidate,
        prober: HTTPProber,
    ) -> ParserFindings:
        url = candidate.full_url
        resp = await prober.probe_get(url)
        body = resp.body
        content_type = resp.headers.get("content-type", "")

        indicators: list[str] = []

        # Stack trace detection
        has_stack = any(p.search(body) for p in _STACK_TRACE_PATTERNS)
        if has_stack:
            indicators.append("stack_trace_detected")

        # JSON error leak (only for JSON responses)
        has_json_error = False
        if "json" in content_type.lower() or body.lstrip().startswith(b"{"):
            has_json_error = any(p.search(body) for p in _JSON_ERROR_PATTERNS)
            if has_json_error:
                indicators.append("json_error_leak")

        # Debug page
        has_debug = any(p.search(body) for p in _DEBUG_PATTERNS)
        if has_debug:
            indicators.append("debug_page_detected")

        # Reflection probe: inject a UUID marker into a param
        has_reflected = False
        reflected_in: str | None = None
        if candidate.param_names:
            marker = f"eve-{uuid.uuid4().hex[:16]}"
            probe_url = f"{url}{'&' if '?' in url else '?'}{candidate.param_names[0]}={marker}"
            try:
                reflect_resp = await prober.probe_get(probe_url)
                if marker.encode() in reflect_resp.body:
                    has_reflected = True
                    reflected_in = candidate.param_names[0]
                    indicators.append(f"reflected_input_in:{reflected_in}")
            except Exception as exc:
                log.debug("eve.parser.reflection_error", url=probe_url, error=str(exc))

        return ParserFindings(
            content_type=content_type,
            has_reflected_input=has_reflected,
            reflected_in=reflected_in,
            has_json_error_leak=has_json_error,
            has_stack_trace=has_stack,
            has_debug_info=has_debug,
            risk_indicators=tuple(indicators),
        )
