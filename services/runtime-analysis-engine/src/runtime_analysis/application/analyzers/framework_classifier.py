from __future__ import annotations

import re

from runtime_analysis.application.analyzers.hydration_analyzer import HydrationResult
from runtime_analysis.domain.value_objects.framework_fingerprint import (
    FrameworkFingerprint,
)

_HEADER_FRAMEWORK_MAP: dict[re.Pattern, str] = {
    re.compile(r"next\.?js", re.IGNORECASE): "NEXT",
    re.compile(r"nuxt", re.IGNORECASE): "NUXT",
    re.compile(r"angular", re.IGNORECASE): "ANGULAR",
    re.compile(r"svelte", re.IGNORECASE): "SVELTE",
    re.compile(r"react", re.IGNORECASE): "REACT",
    re.compile(r"vue", re.IGNORECASE): "VUE",
}

_HEADER_KEYS = ("x-powered-by", "x-generator", "server")


class FrameworkClassifier:
    """
    Assembles all signals (JS probes, hydration markers, response headers)
    into a ranked list of FrameworkFingerprint objects.
    """

    def assemble(
        self,
        js_signals: list[dict],
        hydration: HydrationResult,
        response_headers: dict[str, str],
    ) -> list[FrameworkFingerprint]:
        # Accumulate scores per framework
        scores: dict[str, dict] = {}

        def _add(framework: str, confidence: float, signal: str, version: str | None = None) -> None:
            if framework not in scores:
                scores[framework] = {
                    "framework": framework,
                    "confidence": 0.0,
                    "signals": [],
                    "version": None,
                }
            scores[framework]["confidence"] = min(
                1.0, scores[framework]["confidence"] + confidence
            )
            scores[framework]["signals"].append(signal)
            if version and not scores[framework]["version"]:
                scores[framework]["version"] = version

        # --- JS probe signals ---
        for sig in js_signals:
            fw = sig.get("framework", "").upper()
            if not fw:
                continue
            _add(fw, sig.get("confidence", 0.5), sig.get("evidence", "js_probe"), sig.get("version"))

        # --- Hydration marker ---
        if hydration.framework_hint:
            _add(hydration.framework_hint, 0.6, "hydration_marker")

        # --- Response headers ---
        for hdr in _HEADER_KEYS:
            value = response_headers.get(hdr, "")
            if not value:
                continue
            for pat, fw in _HEADER_FRAMEWORK_MAP.items():
                if pat.search(value):
                    version = self._extract_version(value)
                    _add(fw, 0.7, f"header:{hdr}", version)

        if not scores:
            return [FrameworkFingerprint.build("UNKNOWN", None, 0.0, [])]

        results = []
        for entry in sorted(scores.values(), key=lambda e: e["confidence"], reverse=True):
            results.append(
                FrameworkFingerprint.build(
                    framework=entry["framework"],
                    version_hint=entry["version"],
                    confidence=min(1.0, entry["confidence"]),
                    signals=entry["signals"],
                )
            )
        return results

    def _extract_version(self, header_value: str) -> str | None:
        match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", header_value)
        return match.group(0) if match else None
