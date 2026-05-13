from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class BundlerSignature(BaseModel):
    """Detected bundler characteristics for a set of JS files."""

    model_config = ConfigDict(frozen=True)

    bundler: Literal["WEBPACK", "VITE", "ROLLUP", "PARCEL", "UNKNOWN"] = "UNKNOWN"
    version_hint: str | None = None
    chunk_strategy: Literal["LAZY", "EAGER", "MIXED"] = "EAGER"
    has_source_maps: bool = False
    chunk_count: int = 0
    webpack_major: int | None = None
