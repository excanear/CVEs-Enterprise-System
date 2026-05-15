"""RemediationPlan — actionable remediation steps for an exposure cluster."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RemediationPlan:
    """Template-based remediation steps, optionally enriched by LLM summarization."""

    cluster_id: str
    exposure_type: str
    steps: list[str]
    llm_enriched: bool = False
    llm_narrative: str | None = None
    template_id: str = ""       # key into TEMPLATES dict, for traceability
