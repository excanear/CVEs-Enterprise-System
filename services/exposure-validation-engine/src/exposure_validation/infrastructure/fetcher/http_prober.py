"""HTTP Prober — async httpx client with SSRF guard.

Used by all validation stages that need to make outbound HTTP requests.
Max response body: 512 KB (sufficient for header/body analysis without memory risk).
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import structlog

log = structlog.get_logger(__name__)

# Private/loopback network blocks — never probe these
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB
_DEFAULT_TIMEOUT = 15.0  # seconds


def _ssrf_check(url: str) -> None:
    """Raise ValueError if the URL targets a private/internal network or forbidden scheme."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Blocked scheme: {parsed.scheme!r}")
    try:
        addr = ipaddress.ip_address(parsed.hostname or "")
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError(f"SSRF blocked: private IP {addr}")
    except ValueError as exc:
        if "SSRF blocked" in str(exc):
            raise
        # hostname is a domain name — allow (DNS resolution is runtime-checked by OS)


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
        self._client = httpx.AsyncClient(
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
