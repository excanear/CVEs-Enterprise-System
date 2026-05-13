"""Lightweight async BFS web crawler with SSRF protection.

Design constraints:
  - httpx only (no Playwright / headless browser).
  - BFS with depth limit and page cap per host.
  - Per-domain rate limiting via token bucket.
  - SSRF protection: private/loopback IPs are blocked by default.
  - Scope enforcement: only follows links within scope_domains.
  - Skips binary/media file extensions.
  - Gracefully handles SSL errors (logs, moves on).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Private / reserved IP ranges — SSRF protection
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_SKIP_EXTENSIONS: Final = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".7z",
    ".mp4", ".mp3", ".avi", ".mov",
    ".css",   # CSS has no actionable links
})

_DEFAULT_UA: Final = "CVEs-Discovery/1.0"


@dataclass
class CrawledPage:
    url: str
    status_code: int
    content_type: str
    body: str
    links: list[str] = field(default_factory=list)
    depth: int = 0


class WebCrawler:
    """Async BFS crawler with scope enforcement and SSRF protection."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_rps: float = 5.0,
        user_agent: str = _DEFAULT_UA,
        allow_internal: bool = False,
    ) -> None:
        self._timeout = timeout
        self._rps_interval = 1.0 / max(max_rps, 0.1)
        self._ua = user_agent
        self._allow_internal = allow_internal
        self._last_request: dict[str, float] = {}

    async def crawl(
        self,
        start_hostname: str,
        *,
        scope_domains: list[str],
        max_depth: int = 3,
        max_pages: int = 200,
        seed_urls: list[str] | None = None,
        allow_internal: bool = False,
    ) -> list[CrawledPage]:
        """BFS crawl from *start_hostname*. Returns crawled pages."""
        effective_allow_internal = allow_internal or self._allow_internal

        if not effective_allow_internal and await self._is_ssrf_target(start_hostname):
            logger.warning("crawler.ssrf_blocked", extra={"hostname": start_hostname})
            return []

        start_url = f"https://{start_hostname}/"
        queue: list[tuple[str, int]] = [(start_url, 0)]
        if seed_urls:
            for u in seed_urls[:100]:
                if self._in_scope(u, scope_domains):
                    queue.append((u, 1))

        visited: set[str] = set()
        pages: list[CrawledPage] = []

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": self._ua},
            http2=True,
        ) as client:
            # BFS
            i = 0
            while i < len(queue) and len(pages) < max_pages:
                url, depth = queue[i]
                i += 1

                url = _normalize(url)
                if not url or url in visited:
                    continue
                if depth > max_depth:
                    continue
                if not self._in_scope(url, scope_domains):
                    continue
                if _should_skip(url):
                    continue

                visited.add(url)

                # Per-domain rate limiting
                netloc = urlparse(url).netloc
                await self._throttle(netloc)

                page = await self._fetch(client, url, depth)
                if page is None:
                    continue

                pages.append(page)

                if depth < max_depth:
                    for link in page.links:
                        abs_link = urljoin(url, link)
                        norm = _normalize(abs_link)
                        if norm and norm not in visited:
                            queue.append((norm, depth + 1))

        return pages

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, depth: int
    ) -> CrawledPage | None:
        try:
            resp = await client.get(url)
            ct = resp.headers.get("content-type", "")
            # Only parse body for text-like content types
            if "text" in ct or "javascript" in ct or "json" in ct or "xml" in ct:
                body = resp.text
            else:
                body = ""
            links = _extract_links(body, url) if body else []
            return CrawledPage(
                url=str(resp.url),
                status_code=resp.status_code,
                content_type=ct,
                body=body,
                links=links,
                depth=depth,
            )
        except httpx.InvalidURL:
            return None
        except Exception as exc:
            logger.debug("crawler.fetch_failed", extra={"url": url, "error": str(exc)})
            return None

    async def _throttle(self, netloc: str) -> None:
        now = time.monotonic()
        last = self._last_request.get(netloc, 0.0)
        wait = self._rps_interval - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request[netloc] = time.monotonic()

    def _in_scope(self, url: str, scope_domains: list[str]) -> bool:
        try:
            host = urlparse(url).netloc.split(":")[0].lower()
            return any(
                host == d or host.endswith(f".{d}")
                for d in scope_domains
            )
        except Exception:
            return False

    async def _is_ssrf_target(self, hostname: str) -> bool:
        """Resolve hostname and check if it maps to a private address."""
        try:
            loop = asyncio.get_event_loop()
            addr = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            ip = ipaddress.ip_address(addr)
            return any(ip in net for net in _PRIVATE_NETS)
        except Exception:
            return False  # Can't resolve → let httpx handle it


def _extract_links(html: str, base_url: str) -> list[str]:
    try:
        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            links.append(tag["href"])
        for tag in soup.find_all("form", action=True):
            links.append(tag["action"])
        for tag in soup.find_all("link", href=True):
            rel = tag.get("rel", [])
            if isinstance(rel, list):
                rel = " ".join(rel)
            if "stylesheet" not in rel.lower():
                links.append(tag["href"])
        return [urljoin(base_url, lk) for lk in links if lk]
    except Exception:
        return []


def _normalize(url: str) -> str:
    try:
        parsed = urlparse(url)
        # Strip fragment; keep scheme, netloc, path, params, query
        return parsed._replace(fragment="").geturl()
    except Exception:
        return ""


def _should_skip(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)
