from __future__ import annotations

import re
from dataclasses import dataclass


_HYDRATION_MISMATCH_PATTERNS = [
    re.compile(r"hydration", re.IGNORECASE),
    re.compile(r"did not match", re.IGNORECASE),
    re.compile(r"server.rendered", re.IGNORECASE),
    re.compile(r"content does not match", re.IGNORECASE),
    re.compile(r"Warning: Expected server HTML", re.IGNORECASE),
]

_FRAMEWORK_MARKER_KEYS = {
    "nextData": "NEXT",
    "nuxtData": "NUXT",
    "dataReactRoot": "REACT",
    "dataServerRendered": "VUE",
    "ngVersion": "ANGULAR",
    "inertia": "INERTIA",
}


@dataclass
class HydrationResult:
    framework_hint: str | None
    ssr_detected: bool
    html_bytes_before: int
    html_bytes_after: int
    has_hydration_mismatch: bool
    hydration_delta_bytes: int


class HydrationAnalyzer:
    """Analyses SSR hydration markers and DOM delta to classify the framework."""

    def analyze(
        self,
        html_before: str,
        html_after: str,
        markers: dict,
        console_errors: list[str],
    ) -> HydrationResult:
        bytes_before = len(html_before.encode())
        bytes_after = len(html_after.encode())
        delta = bytes_after - bytes_before

        # Detect framework from marker keys
        framework_hint: str | None = None
        ssr_detected = bool(markers)
        for key, framework in _FRAMEWORK_MARKER_KEYS.items():
            if markers.get(key):
                framework_hint = framework
                break

        # Detect hydration mismatch from console errors
        has_mismatch = any(
            pat.search(err)
            for err in console_errors
            for pat in _HYDRATION_MISMATCH_PATTERNS
        )

        return HydrationResult(
            framework_hint=framework_hint,
            ssr_detected=ssr_detected,
            html_bytes_before=bytes_before,
            html_bytes_after=bytes_after,
            has_hydration_mismatch=has_mismatch,
            hydration_delta_bytes=delta,
        )
