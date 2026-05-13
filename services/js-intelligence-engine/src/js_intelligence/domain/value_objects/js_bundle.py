from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class JSBundle(BaseModel):
    """Value object representing a single downloaded JavaScript bundle."""

    model_config = ConfigDict(frozen=True)

    url: str
    content_hash: str  # sha256 hex
    size_bytes: int = Field(ge=0)
    is_minified: bool = False
    bundler: Literal["WEBPACK", "VITE", "ROLLUP", "PARCEL", "UNKNOWN"] = "UNKNOWN"
    chunk_id: str | None = None
    source_map_url: str | None = None
