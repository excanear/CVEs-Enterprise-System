"""PlaywrightProber — single-context on-demand browser probe for SPAs.

Only instantiated when the detection stage determines that the target is a
SPA (bundler=WEBPACK or VITE detected in the signal's raw metadata).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import structlog
from playwright.async_api import async_playwright

from exposure_validation.infrastructure.fetcher.http_prober import (
    ProbeResponse,
    _PRIVATE_NETS,
    _ALLOWED_SCHEMES,
    _ssrf_check,
    _MAX_RESPONSE_BYTES,
)

log = structlog.get_logger(__name__)

_PLAYWRIGHT_TIMEOUT_MS = 20_000  # 20 s per page


class PlaywrightProber:
    """Launches a single Playwright browser context for one probe, then closes it.

    Not pooled — call on-demand, one at a time per validation job.
    """

    async def probe(self, url: str) -> ProbeResponse:
        """Navigate to *url* and return response metadata."""
        _ssrf_check(url)
        t0 = time.monotonic()
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                captured_status: int | None = None
                captured_headers: dict[str, str] = {}

                async def _on_response(response: object) -> None:
                    nonlocal captured_status, captured_headers
                    # Only capture the main frame navigation response
                    if hasattr(response, "url") and response.url == url:  # type: ignore[union-attr]
                        captured_status = response.status  # type: ignore[union-attr]
                        captured_headers = dict(await response.all_headers())  # type: ignore[union-attr]

                page.on("response", _on_response)
                await page.goto(url, timeout=_PLAYWRIGHT_TIMEOUT_MS, wait_until="networkidle")

                content_bytes = (await page.content()).encode()[:_MAX_RESPONSE_BYTES]
                elapsed = (time.monotonic() - t0) * 1000

                await browser.close()

            return ProbeResponse(
                url=url,
                status_code=captured_status,
                headers=captured_headers,
                body=content_bytes,
                response_time_ms=round(elapsed, 2),
            )
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            log.warning("playwright_prober.failed", url=url, error=str(exc))
            return ProbeResponse(
                url=url,
                status_code=None,
                headers={},
                body=b"",
                response_time_ms=round(elapsed, 2),
                error=str(exc),
            )
