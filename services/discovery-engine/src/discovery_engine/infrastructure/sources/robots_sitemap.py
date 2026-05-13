"""robots.txt and sitemap.xml URL discovery.

Strategy:
  1. Fetch /robots.txt → extract Sitemap: directives + Disallow/Allow paths.
  2. Fetch /sitemap.xml (and any sitemaps found in robots.txt).
  3. Recursively parse sitemap index files (up to _MAX_SITEMAP_DEPTH levels).
  4. Collect all <loc> URLs; return the merged, deduplicated list.

This is intentionally lightweight — no browser, just httpx.
"""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Final
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

_MAX_SITEMAP_DEPTH: Final = 3
_MAX_URLS_RETURNED: Final = 5000
_SITEMAP_NS: Final = "http://www.sitemaps.org/schemas/sitemap/0.9"


class RobotsSitemapSource:
    """Discovers URLs via robots.txt and sitemap.xml."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        user_agent: str = "CVEs-Discovery/1.0",
    ) -> None:
        self._timeout = timeout
        self._ua = user_agent

    async def discover(self, hostname: str) -> list[str]:
        """Return all URLs discovered for *hostname* via robots.txt + sitemaps."""
        urls: list[str] = []

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": self._ua},
        ) as client:
            for scheme in ("https", "http"):
                base = f"{scheme}://{hostname}"
                try:
                    robots_paths, sitemap_from_robots = await self._parse_robots(client, base)
                    urls.extend(robots_paths)

                    # Sitemaps announced in robots.txt + canonical /sitemap.xml
                    sitemap_urls_to_fetch = list(sitemap_from_robots) or [f"{base}/sitemap.xml"]
                    fetch_tasks = [
                        self._fetch_sitemap(client, u, depth=0)
                        for u in sitemap_urls_to_fetch
                    ]
                    sitemap_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
                    for result in sitemap_results:
                        if not isinstance(result, Exception):
                            urls.extend(result)
                    break  # Stop trying http if https succeeded
                except Exception:
                    continue

        # Deduplicate, preserve order, cap
        seen: set[str] = set()
        deduped: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped[:_MAX_URLS_RETURNED]

    async def _parse_robots(
        self,
        client: httpx.AsyncClient,
        base_url: str,
    ) -> tuple[list[str], list[str]]:
        """Fetch robots.txt. Returns (path_urls, sitemap_urls)."""
        paths: list[str] = []
        sitemaps: list[str] = []
        try:
            resp = await client.get(f"{base_url}/robots.txt")
            if resp.status_code != 200:
                return paths, sitemaps

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lower = line.lower()

                if lower.startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    if sitemap_url.startswith("http"):
                        sitemaps.append(sitemap_url)

                elif lower.startswith("disallow:") or lower.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    # Skip wildcard patterns and root
                    if path and path != "/" and "*" not in path and "$" not in path:
                        full_url = urljoin(base_url, path)
                        paths.append(full_url)

        except Exception as exc:
            logger.debug("robots.fetch_failed", extra={"url": base_url, "error": str(exc)})

        return paths, sitemaps

    async def _fetch_sitemap(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        depth: int,
    ) -> list[str]:
        """Recursively fetch a sitemap or sitemap index. Returns <loc> URLs."""
        if depth > _MAX_SITEMAP_DEPTH:
            return []

        urls: list[str] = []
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return urls

            try:
                root = ET.fromstring(resp.text)
            except ET.ParseError:
                logger.debug("sitemap.parse_error", extra={"url": url})
                return urls

            # Strip namespace from tag name
            tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag

            if tag == "sitemapindex":
                # Nested sitemaps — recurse
                child_tasks = []
                for loc_elem in root.findall(f"{{{_SITEMAP_NS}}}sitemap/{{{_SITEMAP_NS}}}loc"):
                    child_url = (loc_elem.text or "").strip()
                    if child_url:
                        child_tasks.append(self._fetch_sitemap(client, child_url, depth=depth + 1))
                results = await asyncio.gather(*child_tasks, return_exceptions=True)
                for result in results:
                    if not isinstance(result, Exception):
                        urls.extend(result)
            else:
                # Regular sitemap — collect <loc>
                for loc_elem in root.findall(f".//{{{_SITEMAP_NS}}}loc"):
                    loc_url = (loc_elem.text or "").strip()
                    if loc_url:
                        urls.append(loc_url)

        except Exception as exc:
            logger.debug("sitemap.error", extra={"url": url, "error": str(exc)})

        return urls
