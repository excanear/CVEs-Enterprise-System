from __future__ import annotations

import ipaddress
import logging
import re
import socket
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

# Same private ranges as js_fetcher.py — SSRF guard before building URL list
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Match <script src="..."> and <script type="module" src="...">
_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
)

# Match <link rel="modulepreload" href="..."> and <link rel="preload" as="script" href="...">
_MODULEPRELOAD_RE = re.compile(
    r'<link[^>]+(?:rel=["\'](?:modulepreload|preload)["\'][^>]*href=["\']([^"\']+)["\']'
    r'|href=["\']([^"\']+)["\'][^>]*rel=["\'](?:modulepreload|preload)["\'])',
    re.IGNORECASE,
)

# Match webpack async chunk patterns:  r.e(chunkId), __webpack_require__.e("chunk-name")
_WEBPACK_CHUNK_LOAD_RE = re.compile(
    r'__webpack_require__\.e\(["\']?([^"\')\s]+)["\']?\)',
    re.IGNORECASE,
)

# Vite __vite__mapDeps([n, m, ...]) — file indices into importedChunks
_VITE_MAP_DEPS_RE = re.compile(r"__vite__mapDeps\(\[([^\]]+)\]", re.IGNORECASE)

# .js extension or common bundle patterns
_JS_URL_RE = re.compile(r"\.m?js(\?[^\"']*)?$", re.IGNORECASE)


def _is_private(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return True
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        return any(ip in net for net in _PRIVATE_NETS)
    except Exception:
        return True  # fail-closed


class BundleDiscoverer:
    """Discovers JS bundle URLs from an HTML page."""

    def discover(
        self,
        html: str,
        base_url: str,
        max_js_files: int = 50,
    ) -> list[str]:
        """Extract and return absolute JS bundle URLs from an HTML document.

        Filters:
        - Only .js / .mjs files
        - Private IPs are excluded (SSRF guard)
        - Capped at max_js_files
        """
        urls: list[str] = []
        seen: set[str] = set()

        def _add(raw_url: str) -> None:
            if not raw_url or raw_url.startswith("data:"):
                return
            absolute = _absolutize(raw_url, base_url)
            if absolute in seen:
                return
            if not _JS_URL_RE.search(absolute.split("?")[0]):
                return
            if _is_private(absolute):
                log.debug("bundle_discoverer.ssrf_blocked", extra={"url": absolute})
                return
            seen.add(absolute)
            urls.append(absolute)

        for m in _SCRIPT_SRC_RE.finditer(html):
            _add(m.group(1))

        for m in _MODULEPRELOAD_RE.finditer(html):
            href = m.group(1) or m.group(2)
            if href:
                _add(href)

        return urls[:max_js_files]


def _absolutize(url: str, base: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("//"):
        scheme = urlparse(base).scheme or "https"
        return f"{scheme}:{url}"
    return urljoin(base, url)
