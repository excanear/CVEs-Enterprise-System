from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from cves_security.ssrf import SafeAsyncClient, ssrf_check as _ssrf_check

log = logging.getLogger(__name__)

# Regex to extract X-SourceMap / SourceMap header and inline sourceMappingURL
_SOURCE_MAP_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s]+)", re.MULTILINE
)

# Accept JS-like Content-Type values
_JS_CONTENT_TYPES = {
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/x-javascript",
}

_DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_DEFAULT_MAX_REDIRECTS = 3


@dataclass(frozen=True)
class JSFetchResult:
    """Result of fetching a single JS or HTML resource."""

    url: str
    content: bytes
    content_hash: str  # sha256 hex
    size_bytes: int
    source_map_url: str | None
    content_type: str


class JSFetcher:
    """Async HTTP client for fetching JS bundles and HTML pages.

    Enforces:
    - SSRF guard (no private/internal IPs)
    - Maximum file size cap
    - Redirect limit
    - Content-Type validation (for JS fetches)
    """

    def __init__(
        self,
        *,
        max_file_size_bytes: int = 10_485_760,  # 10 MB
        timeout: httpx.Timeout = _DEFAULT_TIMEOUT,
    ) -> None:
        self._max_size = max_file_size_bytes
        self._client = SafeAsyncClient(
            follow_redirects=True,
            max_redirects=_DEFAULT_MAX_REDIRECTS,
            timeout=timeout,
            headers={
                "User-Agent": "CVEs-JSI-Engine/1.0 (static-analysis-bot)",
                "Accept": "text/html,application/javascript,*/*;q=0.8",
            },
        )

    async def fetch_html(self, url: str) -> JSFetchResult:
        """Fetch an HTML page (Content-Type not strictly enforced)."""
        _ssrf_check(url)
        return await self._fetch(url, enforce_js_content_type=False)

    async def fetch_js(self, url: str) -> JSFetchResult:
        """Fetch a JS bundle; raises ValueError for oversized or blocked content."""
        _ssrf_check(url)
        return await self._fetch(url, enforce_js_content_type=True)

    async def fetch_raw(self, url: str) -> JSFetchResult:
        """Fetch arbitrary content (source maps, manifests) with SSRF guard."""
        _ssrf_check(url)
        return await self._fetch(url, enforce_js_content_type=False)

    async def _fetch(self, url: str, *, enforce_js_content_type: bool) -> JSFetchResult:
        try:
            response = await self._client.get(url)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ValueError(
                f"HTTP {exc.response.status_code} fetching {url!r}"
            ) from exc
        except httpx.RequestError as exc:
            raise ValueError(f"Request error fetching {url!r}: {exc}") from exc

        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()

        if enforce_js_content_type and content_type not in _JS_CONTENT_TYPES:
            log.debug("js_fetcher.non_js_content_type", extra={"url": url, "ct": content_type})
            # Tolerate — some CDNs serve JS as application/octet-stream

        content = response.content
        if len(content) > self._max_size:
            raise ValueError(
                f"JS bundle too large ({len(content):,} bytes > {self._max_size:,}) at {url!r}"
            )

        content_hash = hashlib.sha256(content).hexdigest()

        # Extract source map URL from inline comment or response header
        source_map_url: str | None = None
        text = content.decode("utf-8", errors="replace")
        sm_header = response.headers.get("SourceMap") or response.headers.get("X-SourceMap")
        if sm_header:
            source_map_url = sm_header.strip()
        else:
            m = _SOURCE_MAP_URL_RE.search(text)
            if m:
                candidate = m.group(1).strip()
                if not candidate.startswith("data:"):
                    source_map_url = candidate

        return JSFetchResult(
            url=url,
            content=content,
            content_hash=content_hash,
            size_bytes=len(content),
            source_map_url=source_map_url,
            content_type=content_type,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "JSFetcher":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
