"""Compliance framework mapper.

Maps each ExposureType to controls in:
  - OWASP Top 10 (2021)
  - CWE
  - PCI-DSS 4.0
  - ISO 27001:2022
  - NIST CSF 2.0
"""
from __future__ import annotations

from reporting.domain.value_objects.compliance_finding import ComplianceFinding

# ── Framework lookup tables ────────────────────────────────────────────────────

OWASP_TOP10_2021: dict[str, list[str]] = {
    "MISSING_AUTH":            ["A01:2021 – Broken Access Control", "A07:2021 – Identification and Authentication Failures"],
    "EXPOSED_API":             ["A05:2021 – Security Misconfiguration"],
    "CORS_MISCONFIGURATION":   ["A05:2021 – Security Misconfiguration"],
    "SECURITY_HEADER_MISSING": ["A05:2021 – Security Misconfiguration"],
    "PATH_TRAVERSAL":          ["A01:2021 – Broken Access Control", "A03:2021 – Injection"],
    "INJECTION_SURFACE":       ["A03:2021 – Injection"],
    "EXPOSED_ROUTE":           ["A01:2021 – Broken Access Control"],
    "WEBSOCKET_UNPROTECTED":   ["A01:2021 – Broken Access Control", "A07:2021 – Identification and Authentication Failures"],
}

CWE_MAP: dict[str, list[str]] = {
    "MISSING_AUTH":            ["CWE-306", "CWE-862"],
    "EXPOSED_API":             ["CWE-200", "CWE-284"],
    "CORS_MISCONFIGURATION":   ["CWE-942", "CWE-346"],
    "SECURITY_HEADER_MISSING": ["CWE-693", "CWE-116"],
    "PATH_TRAVERSAL":          ["CWE-22", "CWE-36"],
    "INJECTION_SURFACE":       ["CWE-89", "CWE-78", "CWE-79"],
    "EXPOSED_ROUTE":           ["CWE-200", "CWE-284"],
    "WEBSOCKET_UNPROTECTED":   ["CWE-306", "CWE-287"],
}

PCI_DSS_40: dict[str, list[str]] = {
    "MISSING_AUTH":            ["Req 6.2.4", "Req 8.2.1"],
    "EXPOSED_API":             ["Req 6.4.1", "Req 6.3.2"],
    "CORS_MISCONFIGURATION":   ["Req 6.2.4"],
    "SECURITY_HEADER_MISSING": ["Req 6.4.1"],
    "PATH_TRAVERSAL":          ["Req 6.2.4"],
    "INJECTION_SURFACE":       ["Req 6.2.4"],
    "EXPOSED_ROUTE":           ["Req 6.4.1"],
    "WEBSOCKET_UNPROTECTED":   ["Req 6.4.1"],
}

ISO_27001_2022: dict[str, list[str]] = {
    "MISSING_AUTH":            ["A.9.4.1", "A.9.4.2"],
    "EXPOSED_API":             ["A.13.1.3", "A.14.2.1"],
    "CORS_MISCONFIGURATION":   ["A.14.1.2"],
    "SECURITY_HEADER_MISSING": ["A.14.1.2"],
    "PATH_TRAVERSAL":          ["A.14.2.1", "A.9.4.1"],
    "INJECTION_SURFACE":       ["A.14.2.1"],
    "EXPOSED_ROUTE":           ["A.13.1.3", "A.9.4.1"],
    "WEBSOCKET_UNPROTECTED":   ["A.13.2.1"],
}

NIST_CSF_20: dict[str, list[str]] = {
    "MISSING_AUTH":            ["PR.AC-1", "PR.AC-4"],
    "EXPOSED_API":             ["PR.AC-3", "DE.CM-1"],
    "CORS_MISCONFIGURATION":   ["PR.IP-1"],
    "SECURITY_HEADER_MISSING": ["PR.IP-1"],
    "PATH_TRAVERSAL":          ["PR.AC-4"],
    "INJECTION_SURFACE":       ["PR.IP-1", "DE.CM-8"],
    "EXPOSED_ROUTE":           ["PR.AC-3"],
    "WEBSOCKET_UNPROTECTED":   ["PR.AC-3", "PR.DS-2"],
}


def map_exposure(exposure: dict) -> ComplianceFinding:
    """Return a ComplianceFinding for a single exposure record."""
    etype = exposure.get("exposure_type", "").upper()
    return ComplianceFinding(
        exposure_id=exposure.get("exposure_id", ""),
        target_url=exposure.get("target_url", ""),
        exposure_type=etype,
        tier=exposure.get("tier", "LOW"),
        composite_score=float(exposure.get("composite_score", 0)),
        owasp_top10=OWASP_TOP10_2021.get(etype, []),
        cwe_ids=CWE_MAP.get(etype, []),
        pci_dss_40=PCI_DSS_40.get(etype, []),
        iso_27001_2022=ISO_27001_2022.get(etype, []),
        nist_csf_20=NIST_CSF_20.get(etype, []),
    )


def map_exposures(exposures: list[dict]) -> list[ComplianceFinding]:
    """Map a list of exposure records to ComplianceFinding objects."""
    return [map_exposure(e) for e in exposures]
