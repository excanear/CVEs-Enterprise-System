from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SourceMapEntry(BaseModel):
    """Maps a generated JS location back to its original source file."""

    model_config = ConfigDict(frozen=True)

    generated_file: str
    original_file: str
    symbols: tuple[str, ...] = ()
