from __future__ import annotations

import re
from collections import Counter

from js_intelligence.domain.value_objects.bundler_signature import BundlerSignature

# ── Webpack 4 signals ─────────────────────────────────────────────────────────
_WP4_PATTERNS = [
    re.compile(r"webpackJsonp\b"),
    re.compile(r'__webpack_require__\s*\.\s*p\s*='),
    re.compile(r"webpackBootstrap"),
]

# ── Webpack 5 signals ─────────────────────────────────────────────────────────
_WP5_PATTERNS = [
    re.compile(r"__webpack_modules__"),
    re.compile(r"__webpack_chunk_load__"),
    re.compile(r'webpack/runtime/chunk\s+loaded'),
    re.compile(r"__webpack_require__\.f\b"),
]

# ── Vite signals ──────────────────────────────────────────────────────────────
_VITE_PATTERNS = [
    re.compile(r"import\.meta\.hot"),
    re.compile(r"__vite__mapDeps"),
    re.compile(r"@vite/client"),
    re.compile(r"vite/modulepreload-polyfill"),
]

# ── Rollup signals ────────────────────────────────────────────────────────────
_ROLLUP_PATTERNS = [
    re.compile(r"/\*\s*rollup\s*\*/", re.IGNORECASE),
    re.compile(r"createCommonjsModule"),
    re.compile(r"_interopRequireDefault"),
]

# ── Parcel signals ────────────────────────────────────────────────────────────
_PARCEL_PATTERNS = [
    re.compile(r"parcelRequire"),
    re.compile(r"HMR_HOST"),
    re.compile(r"\$[a-f0-9]{16}\$exports"),  # Parcel scope hashes
]

# lazy-loading signals — chunk loading at runtime
_LAZY_PATTERNS = [
    re.compile(r"__webpack_chunk_load__"),
    re.compile(r"import\.meta\.glob"),
    re.compile(r"loadChildren\s*:"),
    re.compile(r"React\.lazy\("),
    re.compile(r"defineAsyncComponent"),
    re.compile(r'import\s*\(\s*[\'"]'),
]


def _score(content: str, patterns: list[re.Pattern]) -> int:
    return sum(1 for p in patterns if p.search(content))


class BundlerDetector:
    """Detects bundler type and chunk strategy from JS bundle content."""

    def detect(self, contents: list[str]) -> BundlerSignature:
        """Run majority-vote detection across multiple JS file contents.

        Args:
            contents: List of JS file text content strings.

        Returns:
            BundlerSignature with detected bundler and metadata.
        """
        votes: Counter[str] = Counter()
        has_source_maps = False
        chunk_count = len(contents)
        lazy_score = 0

        for content in contents:
            wp4 = _score(content, _WP4_PATTERNS)
            wp5 = _score(content, _WP5_PATTERNS)
            vite = _score(content, _VITE_PATTERNS)
            rollup = _score(content, _ROLLUP_PATTERNS)
            parcel = _score(content, _PARCEL_PATTERNS)

            # Each file votes for its most likely bundler
            scores = {
                "WEBPACK4": wp4,
                "WEBPACK5": wp5,
                "VITE": vite,
                "ROLLUP": rollup,
                "PARCEL": parcel,
            }
            winner = max(scores, key=lambda k: scores[k])
            if scores[winner] > 0:
                votes[winner] += scores[winner]

            lazy_score += _score(content, _LAZY_PATTERNS)

            if "sourceMappingURL=" in content or "//# sourceURL=" in content:
                has_source_maps = True

        if not votes:
            return BundlerSignature(
                bundler="UNKNOWN",
                chunk_strategy="EAGER",
                has_source_maps=has_source_maps,
                chunk_count=chunk_count,
            )

        top_bundler_key = votes.most_common(1)[0][0]

        bundler_map = {
            "WEBPACK4": "WEBPACK",
            "WEBPACK5": "WEBPACK",
            "VITE": "VITE",
            "ROLLUP": "ROLLUP",
            "PARCEL": "PARCEL",
        }
        bundler = bundler_map.get(top_bundler_key, "UNKNOWN")
        webpack_major = None
        version_hint: str | None = None

        if bundler == "WEBPACK":
            if top_bundler_key == "WEBPACK5":
                webpack_major = 5
                version_hint = "5.x"
            else:
                webpack_major = 4
                version_hint = "4.x"
        elif bundler == "VITE":
            version_hint = _detect_vite_version(contents)

        chunk_strategy: str
        lazy_threshold = max(1, len(contents))
        if lazy_score >= lazy_threshold:
            chunk_strategy = "LAZY"
        elif lazy_score > 0:
            chunk_strategy = "MIXED"
        else:
            chunk_strategy = "EAGER"

        return BundlerSignature(
            bundler=bundler,  # type: ignore[arg-type]
            version_hint=version_hint,
            chunk_strategy=chunk_strategy,  # type: ignore[arg-type]
            has_source_maps=has_source_maps,
            chunk_count=chunk_count,
            webpack_major=webpack_major,
        )


_VITE_VERSION_RE = re.compile(r'vite[/\s@v]+(\d+\.\d+)', re.IGNORECASE)


def _detect_vite_version(contents: list[str]) -> str | None:
    for content in contents:
        m = _VITE_VERSION_RE.search(content)
        if m:
            return m.group(1) + ".x"
    return None
