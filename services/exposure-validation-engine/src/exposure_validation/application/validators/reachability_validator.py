"""ReachabilityValidator — checks if the target endpoint is actually reachable.

Uses httpx by default; switches to Playwright on-demand when the signal
metadata indicates a SPA bundler (WEBPACK or VITE).
"""
from __future__ import annotations

import structlog

from exposure_validation.domain.value_objects.exposure_candidate import ExposureCandidate
from exposure_validation.domain.value_objects.reachability_probe import ReachabilityProbeResult
from exposure_validation.infrastructure.fetcher.http_prober import HTTPProber

log = structlog.get_logger(__name__)

_SPA_BUNDLERS = {"WEBPACK", "VITE"}


def _is_spa_target(candidate: ExposureCandidate) -> bool:
    """Return True if any raw signal indicates a SPA bundler."""
    for signal in candidate.raw_signals:
        bundler = signal.get("bundler", "")
        if bundler in _SPA_BUNDLERS:
            return True
    return False


class ReachabilityValidator:
    @staticmethod
    async def check(
        candidate: ExposureCandidate,
        prober: HTTPProber,
    ) -> ReachabilityProbeResult:
        url = candidate.full_url

        # Fast httpx path first
        resp = await prober.probe_get(url)

        if resp.status_code is not None and resp.status_code not in (0, 404, 408):
            return ReachabilityProbeResult(
                endpoint_url=url,
                is_reachable=True,
                http_status=resp.status_code,
                response_time_ms=resp.response_time_ms,
                required_playwright=False,
            )

        # If not reachable via httpx and it's a SPA, try Playwright
        if _is_spa_target(candidate):
            log.debug("eve.reachability.playwright_fallback", url=url)
            try:
                from exposure_validation.infrastructure.browser.playwright_prober import (
                    PlaywrightProber,
                )

                pw_resp = await PlaywrightProber().probe(url)
                if pw_resp.status_code is not None:
                    return ReachabilityProbeResult(
                        endpoint_url=url,
                        is_reachable=True,
                        http_status=pw_resp.status_code,
                        response_time_ms=pw_resp.response_time_ms,
                        required_playwright=True,
                    )
            except Exception as exc:
                log.warning("eve.reachability.playwright_error", url=url, error=str(exc))

        return ReachabilityProbeResult.unreachable(
            url, resp.error or f"HTTP {resp.status_code}"
        )
