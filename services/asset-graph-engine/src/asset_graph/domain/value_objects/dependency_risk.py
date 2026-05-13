"""Value object: DependencyRisk.

Represents a runtime dependency discovered in an Asset bundle with optional
CVE enrichment. CVE edges (:HAS_CVE) are created by the Findings Indexer
(future service); this VO carries risk data as returned by graph queries.
Immutable (frozen Pydantic model).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DependencyRisk(BaseModel):
    model_config = ConfigDict(frozen=True)

    asset_id: str
    asset_url: str | None = None
    dep_id: str
    name: str
    version: str
    ecosystem: str  # npm | pip | maven | gem
    cve_ids: tuple[str, ...] = Field(default_factory=tuple)
    max_cvss: float | None = None

    @property
    def has_known_cves(self) -> bool:
        return len(self.cve_ids) > 0
