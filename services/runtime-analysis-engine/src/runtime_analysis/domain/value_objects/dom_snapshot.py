from __future__ import annotations

from pydantic import BaseModel, Field


class DOMSnapshot(BaseModel, frozen=True):
    """Value object capturing DOM mutation summary between initial load and hydration."""

    html_bytes_before: int = Field(ge=0)
    html_bytes_after: int = Field(ge=0)
    node_additions: int = Field(ge=0)
    node_removals: int = Field(ge=0)
    attr_changes: int = Field(ge=0)
    added_scripts: tuple[str, ...] = ()
    added_forms: tuple[str, ...] = ()

    @property
    def hydration_delta_bytes(self) -> int:
        return self.html_bytes_after - self.html_bytes_before

    @property
    def has_significant_mutations(self) -> bool:
        return (
            self.node_additions > 10
            or self.node_removals > 5
            or abs(self.hydration_delta_bytes) > 1024
        )
