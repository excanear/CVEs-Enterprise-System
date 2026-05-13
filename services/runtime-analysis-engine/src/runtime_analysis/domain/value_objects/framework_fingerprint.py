from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class FrameworkFingerprint(BaseModel, frozen=True):
    """Value object identifying a frontend framework detected during runtime analysis."""

    framework: Literal[
        "REACT", "VUE", "ANGULAR", "NEXT", "NUXT", "SVELTE", "UNKNOWN"
    ]
    version_hint: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    signals: tuple[str, ...] = ()
    cpe_uri: str | None = None

    # CPE URI mapping per framework (no version → wildcard)
    _CPE_MAP: dict[str, str] = {
        "REACT": "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*",
        "VUE": "cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*",
        "ANGULAR": "cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*",
        "NEXT": "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*",
        "NUXT": "cpe:2.3:a:nuxtjs:nuxt:*:*:*:*:*:*:*:*",
        "SVELTE": "cpe:2.3:a:svelte:svelte:*:*:*:*:*:*:*:*",
    }

    @classmethod
    def build(
        cls,
        framework: str,
        version_hint: str | None,
        confidence: float,
        signals: list[str],
    ) -> "FrameworkFingerprint":
        cpe = cls._CPE_MAP.get(framework)  # type: ignore[attr-defined]
        if cpe and version_hint:
            parts = cpe.split(":")
            parts[5] = version_hint
            cpe = ":".join(parts)
        return cls(
            framework=framework,  # type: ignore[arg-type]
            version_hint=version_hint,
            confidence=confidence,
            signals=tuple(signals),
            cpe_uri=cpe,
        )
