"""HTTP Prober — async httpx client with SSRF guard.

Used by all validation stages that need to make outbound HTTP requests.
Max response body: 512 KB (sufficient for header/body analysis without memory risk).

SSRF protection is provided by cves_security.ssrf:
  - DNS-resolves ALL hostnames (domain names are never blindly allowed)
  - Blocks private ranges, metadata endpoints, forbidden schemes
  - SafeAsyncClient re-checks on every redirect hop
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import structlog

from cves_security.ssrf import (
    SafeAsyncClient,
    _ALLOWED_SCHEMES,
    _PRIVATE_NETS,
    ssrf_check as _ssrf_check,
)

log = structlog.get_logger(__name__)

_MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB
_DEFAULT_TIMEOUT = 15.0  # seconds


@dataclass
class ProbeResponse:
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: bytes
    response_time_ms: float
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status_code is not None and 100 <= self.status_code < 500


class HTTPProber:
    """Async HTTP prober with SSRF protection."""

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._client = SafeAsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            http2=True,
            verify=False,  # target may have self-signed certs
        )

    async def probe_get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ssrf_check(url)
        t0 = time.monotonic()
        try:
            resp = await self._client.get(url, headers=headers or {})
            elapsed = (time.monotonic() - t0) * 1000
            body = resp.content[:_MAX_RESPONSE_BYTES]
            return ProbeResponse(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                response_time_ms=round(elapsed, 2),
            )
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            log.warning("http_prober.get_failed", url=url, error=str(exc))
            return ProbeResponse(
                url=url,
                status_code=None,
                headers={},
                body=b"",
                response_time_ms=round(elapsed, 2),
                error=str(exc),
            )

    async def probe_post(
        self,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        _ssrf_check(url)
        t0 = time.monotonic()
        try:
            resp = await self._client.post(url, content=body or b"", headers=headers or {})
            elapsed = (time.monotonic() - t0) * 1000
            resp_body = resp.content[:_MAX_RESPONSE_BYTES]
            return ProbeResponse(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp_body,
                response_time_ms=round(elapsed, 2),
            )
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            log.warning("http_prober.post_failed", url=url, error=str(exc))
            return ProbeResponse(
                url=url,
                status_code=None,
                headers={},
                body=b"",
                response_time_ms=round(elapsed, 2),
                error=str(exc),
            )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HTTPProber":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
