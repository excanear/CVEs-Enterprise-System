from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry
from js_intelligence.infrastructure.fetcher.js_fetcher import JSFetcher, JSFetchResult
from js_intelligence.infrastructure.source_maps.source_map_parser import SourceMapParser

log = logging.getLogger(__name__)

_SAME_ORIGIN_SCHEMES = {"http", "https"}


def _is_same_origin(source_map_url: str, generated_url: str) -> bool:
    """Only allow same-origin source map URLs."""
    try:
        sm = urlparse(source_map_url)
        gen = urlparse(generated_url)
        return sm.scheme == gen.scheme and sm.netloc == gen.netloc
    except Exception:
        return False


class SourceMapAnalyzer:
    """Fetches and parses source maps for a JS bundle."""

    async def analyze(
        self,
        fetch_result: JSFetchResult,
        fetcher: JSFetcher,
    ) -> list[SourceMapEntry]:
        """Attempt to fetch and parse the source map for a given JS bundle.

        Security policy:
        - Only follows same-origin source map URLs.
        - Accepts inline ``data:`` URIs without network request.

        Returns an empty list if no source map is available or parseable.
        """
        source_map_url = fetch_result.source_map_url
        if not source_map_url:
            return []

        # Inline data URI — parse directly without network
        if source_map_url.startswith("data:"):
            return SourceMapParser.parse_json_bytes(
                source_map_url.encode(), fetch_result.url
            )

        # Resolve relative URLs
        if not source_map_url.startswith(("http://", "https://")):
            source_map_url = urljoin(fetch_result.url, source_map_url)

        # Security: same-origin only
        if not _is_same_origin(source_map_url, fetch_result.url):
            log.warning(
                "source_map_analyzer.cross_origin_blocked",
                extra={"sm_url": source_map_url, "js_url": fetch_result.url},
            )
            return []

        try:
            sm_result = await fetcher.fetch_raw(source_map_url)
            return SourceMapParser.parse_json_bytes(sm_result.content, fetch_result.url)
        except Exception as exc:
            log.debug(
                "source_map_analyzer.fetch_error",
                extra={"sm_url": source_map_url, "err": str(exc)},
            )
            return []
