"""Endpoint extractor — mines HTTP endpoints from crawled page bodies.

Extraction strategies:
  1. HTML <a href>          — navigational links.
  2. HTML <form action>     — form submission endpoints.
  3. JavaScript fetch()     — XHR / Fetch API calls.
  4. JavaScript axios.*()   — axios HTTP calls with method inference.
  5. String literals        — API-like path strings in JS bundles.
  6. HTTP headers           — Location, Link, X-Powered-By hints.

API endpoint heuristic: path contains /api/, /graphql, /rest/, /v\d+/, etc.
"""
from __future__ import annotations

import re
from typing import Final
from urllib.parse import parse_qs, urljoin, urlparse

from ...domain.value_objects.endpoint import Endpoint, HttpMethod
from .crawler import CrawledPage

# ── Regex patterns ────────────────────────────────────────────────────────────

# fetch("...") or fetch('...')
_FETCH_RE: Final = re.compile(
    r"""fetch\s*\(\s*['"`]([^'"`\s]{2,500})['"`]""", re.IGNORECASE
)

# axios.get/post/put/patch/delete("...")
_AXIOS_RE: Final = re.compile(
    r"""axios\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]{2,500})['"`]""",
    re.IGNORECASE,
)

# $http.get/post/... (AngularJS)
_ANGULARJS_RE: Final = re.compile(
    r"""\$http\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]{2,500})['"`]""",
    re.IGNORECASE,
)

# API-like paths in string literals: "/api/v1/...", "/graphql", "/rest/..."
_API_PATH_RE: Final = re.compile(
    r"""['"`](/(api|graphql|rest|v\d+|_api|wp-json|rpc|gql)[^'"`<>\s]{0,400})['"`]"""
)

# Generic path strings: "/some/path" in JS
_GENERIC_PATH_RE: Final = re.compile(
    r"""['"`]((?:/[a-zA-Z0-9_.-]{1,64}){2,8}(?:\?[^'"`\s]*)?)['"`]"""
)

# HTML href / action attributes (fallback when BS4 is not used)
_HREF_RE: Final = re.compile(r"""href=['"]([^'"<>\s]{1,500})['"]""", re.IGNORECASE)
_ACTION_RE: Final = re.compile(r"""action=['"]([^'"<>\s]{1,500})['"]""", re.IGNORECASE)
_FORM_METHOD_RE: Final = re.compile(r"""<form[^>]*method=['"](\w+)['"]""", re.IGNORECASE)

# API endpoint path indicators
_API_INDICATORS: Final = frozenset({
    "/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/",
    "/_api/", "/wp-json/", "/rpc/", "/gql", "/query",
})


class EndpointExtractor:
    """Extracts HTTP endpoints from a CrawledPage's body."""

    def extract(self, page: CrawledPage) -> list[Endpoint]:
        if not page.body:
            return []

        endpoints: list[Endpoint] = []
        seen_urls: set[str] = set()
        base = page.url
        ct = page.content_type.lower()
        body = page.body

        def add(
            raw: str,
            method: HttpMethod = HttpMethod.GET,
            source: str = "CRAWLER",
        ) -> None:
            if not raw:
                return
            url = _resolve(raw, base)
            if not url or url in seen_urls:
                return
            seen_urls.add(url)
            path = urlparse(url).path
            params = tuple(parse_qs(urlparse(url).query).keys())
            endpoints.append(Endpoint(
                url=url,
                path=path,
                method=method,
                discovered_from=base,
                source=source,
                parameters=params,
                is_api_endpoint=_is_api(path),
            ))

        is_js = "javascript" in ct or page.url.endswith(".js")
        is_html = "html" in ct or not is_js

        # ── HTML sources ──────────────────────────────────────────────────
        if is_html:
            for m in _HREF_RE.finditer(body):
                add(m.group(1), HttpMethod.GET, "HTML_HREF")

            actions = list(_ACTION_RE.finditer(body))
            methods = list(_FORM_METHOD_RE.finditer(body))
            for i, m in enumerate(actions):
                raw_method = methods[i].group(1).upper() if i < len(methods) else "POST"
                try:
                    http_method = HttpMethod(raw_method)
                except ValueError:
                    http_method = HttpMethod.POST
                add(m.group(1), http_method, "HTML_FORM")

        # ── JavaScript sources ────────────────────────────────────────────
        for m in _FETCH_RE.finditer(body):
            add(m.group(1), HttpMethod.GET, "JS_FETCH")

        for m in _AXIOS_RE.finditer(body):
            try:
                http_method = HttpMethod(m.group(1).upper())
            except ValueError:
                http_method = HttpMethod.GET
            add(m.group(2), http_method, "JS_AXIOS")

        for m in _ANGULARJS_RE.finditer(body):
            try:
                http_method = HttpMethod(m.group(1).upper())
            except ValueError:
                http_method = HttpMethod.GET
            add(m.group(2), http_method, "JS_ANGULARJS")

        for m in _API_PATH_RE.finditer(body):
            add(m.group(1), HttpMethod.GET, "JS_API_STRING")

        # Generic paths only from JS files to avoid false positives in HTML
        if is_js:
            for m in _GENERIC_PATH_RE.finditer(body):
                path_candidate = m.group(1)
                if _is_api(path_candidate):
                    add(path_candidate, HttpMethod.GET, "JS_PATH_STRING")

        return endpoints


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve(raw: str, base: str) -> str:
    """Resolve a raw href/action/JS URL to an absolute URL."""
    raw = raw.strip()
    if not raw:
        return ""
    # Absolute URL
    if raw.startswith(("http://", "https://")):
        return raw
    # Protocol-relative
    if raw.startswith("//"):
        scheme = urlparse(base).scheme or "https"
        return f"{scheme}:{raw}"
    # Root-relative or relative path
    if raw.startswith("/") or not raw.startswith(("#", "javascript:", "mailto:", "tel:")):
        return urljoin(base, raw)
    return ""


def _is_api(path: str) -> bool:
    """Heuristic: does this path look like an API endpoint?"""
    lp = path.lower()
    return any(indicator in lp for indicator in _API_INDICATORS)
