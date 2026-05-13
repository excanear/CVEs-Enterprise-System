from __future__ import annotations

import re
from collections import defaultdict

from js_intelligence.domain.value_objects.hidden_route import HiddenRoute
from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry
from js_intelligence.infrastructure.ast.tree_sitter_parser import ParseResult

# ── Pattern definitions ───────────────────────────────────────────────────────

# React Router: { path: "..." } or path="..." in JSX
_REACT_PATH_RE = re.compile(
    r'''(?:createBrowserRouter|createHashRouter|useRoutes|<Route)\b[^;]{0,2000}?'''
    r'''["']?path["']?\s*[=:]\s*["']([^"']+)["']''',
    re.DOTALL,
)

# Vue Router: { path: '...', component: ... }
_VUE_PATH_RE = re.compile(
    r'''\{\s*["']?path["']?\s*:\s*["']([^"']+)["']\s*,\s*["']?(?:component|children)["']?''',
    re.DOTALL,
)

# Angular: { path: '...', loadChildren: ... }  or  { path: '...', component: ... }
_ANGULAR_PATH_RE = re.compile(
    r'''\{\s*["']?path["']?\s*:\s*["']([^"']+)["']\s*,\s*["']?(?:loadChildren|component|redirectTo)["']?''',
    re.DOTALL,
)

# Generic route-like string: starts with / and looks like a URL path
_GENERIC_PATH_RE = re.compile(r'''["'](/[a-zA-Z0-9_/\-:.]+)["']''')

# Next.js / Nuxt source paths: pages/ or app/ directory convention
_NEXT_PAGE_RE = re.compile(r'(?:pages|app)/([a-zA-Z0-9_/\[\]-]+)(?:\.(?:tsx?|jsx?|vue))?$')

# Confidence weights per pattern type
_CONFIDENCE = {
    "REACT_ROUTER": 0.90,
    "VUE_ROUTER": 0.88,
    "ANGULAR": 0.88,
    "NEXT_JS": 0.85,
    "NUXT": 0.82,
    "INFERRED": 0.40,
}

# Minimum path length and validity
_MIN_PATH_LEN = 2
_INVALID_PATH_RE = re.compile(r'[<>{}|\\^`\s]')


def _normalize_path(path: str) -> str:
    """Normalize a route path string."""
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    return path


def _is_valid_path(path: str) -> bool:
    if len(path) < _MIN_PATH_LEN:
        return False
    if _INVALID_PATH_RE.search(path):
        return False
    # Exclude obvious non-route strings
    if path.endswith((".js", ".css", ".png", ".svg", ".json", ".woff")):
        return False
    return True


class RouteInferenceEngine:
    """Infers hidden routes from JS AST parse results and source map entries."""

    def infer(
        self,
        parse_results: list[ParseResult],
        source_entries: list[SourceMapEntry],
        bundler: str,
    ) -> list[HiddenRoute]:
        """Infer routes from static JS analysis.

        Priority:
        1. Source map entries (highest fidelity — original paths)
        2. Framework-specific route patterns in minified/bundled code
        3. Generic path string fallback

        Returns deduplicated list of HiddenRoute, sorted by confidence desc.
        """
        # path → best HiddenRoute so far
        best: dict[str, HiddenRoute] = {}

        # ── 1. Source map reconstruction (highest fidelity) ────────────────
        self._infer_from_source_maps(source_entries, best)

        # ── 2. Framework patterns per parse result ─────────────────────────
        for pr in parse_results:
            chunk_id = _chunk_id_from_url(pr.source_url)
            self._infer_react(pr, chunk_id, best)
            self._infer_vue(pr, chunk_id, best)
            self._infer_angular(pr, chunk_id, best)

        # ── 3. Pre-extracted route_path_strings from AST ───────────────────
        for pr in parse_results:
            chunk_id = _chunk_id_from_url(pr.source_url)
            for path in pr.route_path_strings:
                path = _normalize_path(path)
                if _is_valid_path(path) and path not in best:
                    best[path] = HiddenRoute(
                        path=path,
                        router_type="INFERRED",
                        confidence=_CONFIDENCE["INFERRED"],
                        discovered_in_chunk=chunk_id,
                    )

        routes = list(best.values())
        routes.sort(key=lambda r: r.confidence, reverse=True)
        return routes

    # ── Private helpers ──────────────────────────────────────────────────────

    def _infer_from_source_maps(
        self,
        source_entries: list[SourceMapEntry],
        best: dict[str, HiddenRoute],
    ) -> None:
        for entry in source_entries:
            m = _NEXT_PAGE_RE.search(entry.original_file)
            if not m:
                continue

            raw_path = m.group(1)
            # Convert Next.js/Nuxt file conventions to route paths
            # e.g. "blog/[id]" → "/blog/:id", "index" → "/"
            route_path = _file_to_route(raw_path)
            if not _is_valid_path(route_path):
                continue

            router_type = "NUXT" if "nuxt" in entry.original_file.lower() else "NEXT_JS"
            confidence = _CONFIDENCE[router_type]

            existing = best.get(route_path)
            if existing is None or existing.confidence < confidence:
                best[route_path] = HiddenRoute(
                    path=route_path,
                    router_type=router_type,  # type: ignore[arg-type]
                    component_hint=entry.original_file,
                    confidence=confidence,
                    discovered_in_chunk=entry.generated_file,
                )

    def _infer_react(
        self, pr: ParseResult, chunk_id: str, best: dict[str, HiddenRoute]
    ) -> None:
        for m in _REACT_PATH_RE.finditer(pr.raw_text):
            path = _normalize_path(m.group(1))
            if not _is_valid_path(path):
                continue
            _upsert(best, path, "REACT_ROUTER", _CONFIDENCE["REACT_ROUTER"], chunk_id)

    def _infer_vue(
        self, pr: ParseResult, chunk_id: str, best: dict[str, HiddenRoute]
    ) -> None:
        for m in _VUE_PATH_RE.finditer(pr.raw_text):
            path = _normalize_path(m.group(1))
            if not _is_valid_path(path):
                continue
            _upsert(best, path, "VUE_ROUTER", _CONFIDENCE["VUE_ROUTER"], chunk_id)

    def _infer_angular(
        self, pr: ParseResult, chunk_id: str, best: dict[str, HiddenRoute]
    ) -> None:
        for m in _ANGULAR_PATH_RE.finditer(pr.raw_text):
            path = _normalize_path(m.group(1))
            if not _is_valid_path(path):
                continue
            _upsert(best, path, "ANGULAR", _CONFIDENCE["ANGULAR"], chunk_id)


def _upsert(
    best: dict[str, HiddenRoute],
    path: str,
    router_type: str,
    confidence: float,
    chunk_id: str,
) -> None:
    existing = best.get(path)
    if existing is None or existing.confidence < confidence:
        best[path] = HiddenRoute(
            path=path,
            router_type=router_type,  # type: ignore[arg-type]
            confidence=confidence,
            discovered_in_chunk=chunk_id,
        )


def _chunk_id_from_url(url: str) -> str:
    """Extract a chunk identifier from a bundle URL."""
    return url.rsplit("/", 1)[-1].split("?")[0] if "/" in url else url


def _file_to_route(file_path: str) -> str:
    """Convert a Next.js/Nuxt file path to a route path.

    Examples:
        index → /
        about → /about
        blog/[id] → /blog/:id
        (marketing)/home → /home   (Next.js route groups)
    """
    # Remove route groups like (marketing)/
    path = re.sub(r'\([^)]+\)/', '', file_path)
    # Remove index suffix
    path = re.sub(r'(/index|^index)$', '', path)
    # Convert [param] to :param
    path = re.sub(r'\[([^\]]+)\]', r':\1', path)
    # Convert [[...param]] or [...param] catch-all
    path = re.sub(r'\[\.\.\.([^\]]+)\]', r'*\1', path)

    route = "/" + path.strip("/") if path else "/"
    return route if route != "//" else "/"
