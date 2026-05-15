"""ComplianceFinding — maps an exposure to security framework controls."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ComplianceFinding:
    """One exposure mapped to all relevant compliance framework controls."""

    exposure_id: str
    target_url: str
    exposure_type: str
    tier: str
    composite_score: float
    owasp_top10: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    pci_dss_40: list[str] = field(default_factory=list)
    iso_27001_2022: list[str] = field(default_factory=list)
    nist_csf_20: list[str] = field(default_factory=list)
