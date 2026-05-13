"""Value object: TrustChain.

Represents a transitive TRUSTS path originating from a given Asset.
Immutable (frozen Pydantic model).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TrustLink(BaseModel):
    model_config = ConfigDict(frozen=True)

    from_asset_id: str
    to_asset_id: str
    trust_type: str = "CORS"
    origin: str | None = None


class TrustChain(BaseModel):
    """A transitive chain of TRUSTS relationships from one Asset."""

    model_config = ConfigDict(frozen=True)

    root_asset_id: str
    chain: tuple[TrustLink, ...] = Field(default_factory=tuple)
    depth: int = Field(ge=0)
    terminal_asset_ids: tuple[str, ...] = Field(default_factory=tuple)
