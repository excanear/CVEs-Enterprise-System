"""cves_security.ssrf — Centralized SSRF protection for all outbound HTTP.

Guards against:
  - RFC 1918 private ranges, link-local, loopback, IPv6 private (fc00::/7, fe80::/10)
  - Cloud metadata endpoints: 169.254.169.254, 100.100.100.200, fd00:ec2::254
  - Redirect-chain SSRF: SafeAsyncClient re-checks EVERY redirect hop via event_hooks
  - DNS-level check: ALL hostnames are fully resolved before the request is allowed
  - Dangerous URL schemes: file, ftp, gopher, ldap, dict, data, blob, javascript
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

# ── Private / reserved address ranges ─────────────────────────────────────────

_PRIVATE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),         # loopback
    ipaddress.ip_network("169.254.0.0/16"),       # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),        # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),            # "This" network (RFC 1122)
]

# Explicit metadata endpoints that must always be blocked regardless of range
_METADATA_ADDRS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset({
    ipaddress.ip_address("169.254.169.254"),    # AWS / GCP / Azure / DigitalOcean IMDS
    ipaddress.ip_address("100.100.100.200"),    # Alibaba Cloud metadata
    ipaddress.ip_address("fd00:ec2::254"),      # AWS IPv6 IMDS
})

_BLOCKED_SCHEMES: frozenset[str] = frozenset({
    "file", "ftp", "ftps", "gopher", "ldap", "ldaps",
    "dict", "data", "blob", "javascript", "ssh",
})

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


# ── Core helpers ───────────────────────────────────────────────────────────────

def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, source: str) -> None:
    """Raise ValueError if *ip* is a private, loopback, or cloud-metadata address."""
    if ip in _METADATA_ADDRS:
        raise ValueError(f"SSRF blocked — metadata endpoint {ip} (source: {source!r})")
    for net in _PRIVATE_NETS:
        if ip in net:
            raise ValueError(f"SSRF blocked — private IP {ip} (source: {source!r})")


def _resolve_and_check(hostname: str) -> None:
    """DNS-resolve *hostname* and block if ANY resolved address is private.

    Checks all addresses returned by getaddrinfo (IPv4 + IPv6).
    Fails closed: unresolvable hostnames raise ValueError.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError as exc:
        raise ValueError(
            f"SSRF blocked — cannot resolve {hostname!r}: {exc}"
        ) from exc
    for *_, sockaddr in infos:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        _check_ip(ip, hostname)


# ── Public API ─────────────────────────────────────────────────────────────────

def ssrf_check(url: str) -> None:
    """Synchronous SSRF validation. DNS-resolves every hostname.

    Raises ValueError if the URL targets a private/metadata address or uses
    a forbidden scheme. Blocks the calling thread briefly for DNS resolution;
    prefer ``async_ssrf_check()`` in async contexts.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    if scheme in _BLOCKED_SCHEMES:
        raise ValueError(f"SSRF blocked — forbidden scheme {scheme!r} in {url!r}")
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"SSRF blocked — unknown scheme {scheme!r} in {url!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"SSRF blocked — no hostname in URL {url!r}")

    # Fast path: literal IP address — no DNS needed
    try:
        ip = ipaddress.ip_address(hostname)
        _check_ip(ip, url)
        return
    except ValueError as exc:
        if "SSRF blocked" in str(exc):
            raise
        # Not a literal IP — full DNS resolution required

    _resolve_and_check(hostname)


async def async_ssrf_check(url: str) -> None:
    """Async SSRF validation. Runs DNS resolution in a thread-pool executor.

    Use this in async contexts to avoid blocking the event loop.
    """
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, ssrf_check, url)


# ── httpx integration ──────────────────────────────────────────────────────────

async def _ssrf_request_hook(request: httpx.Request) -> None:
    """httpx event hook — enforces SSRF check on EVERY request, including redirects."""
    await async_ssrf_check(str(request.url))


class SafeAsyncClient(httpx.AsyncClient):
    """httpx.AsyncClient with per-request SSRF enforcement on every hop.

    Injects an async request event hook that calls ``async_ssrf_check`` before
    each HTTP request. Because httpx fires the hook for every request including
    redirect hops, this eliminates redirect-chain SSRF attacks.

    Drop-in replacement for ``httpx.AsyncClient`` in all scanner services.

    Example::

        async with SafeAsyncClient(follow_redirects=True) as client:
            resp = await client.get("https://example.com")
    """

    def __init__(self, **kwargs: Any) -> None:
        hooks: dict[str, list] = dict(kwargs.pop("event_hooks", {}))
        request_hooks = list(hooks.get("request", []))
        request_hooks.insert(0, _ssrf_request_hook)
        hooks["request"] = request_hooks
        super().__init__(event_hooks=hooks, **kwargs)
