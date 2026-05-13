"""MiddlewareValidator — analyzes HTTP response headers for security misconfigurations."""
from __future__ import annotations

from exposure_validation.domain.value_objects.middleware_findings import MiddlewareFindings
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber


class MiddlewareValidator:
    @staticmethod
    async def analyze(
        url: str,
        prober: HTTPProber,
    ) -> MiddlewareFindings:
        """Probe the URL and return a MiddlewareFindings based on response headers."""
        resp = await prober.probe_get(url)
        return MiddlewareFindings.from_headers(resp.headers)
