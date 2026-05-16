"""Dynamic shell completion helpers for Typer/Click commands."""
from __future__ import annotations

from typing import Any


def complete_scan_status(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("PENDING", "Waiting to start"),
        ("RUNNING", "Currently executing"),
        ("COMPLETED", "Finished successfully"),
        ("FAILED", "Finished with errors"),
        ("CANCELLED", "Manually cancelled"),
        ("PARTIAL", "Partially completed"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_scan_type(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("NETWORK_DISCOVERY", "Discover live hosts and services"),
        ("PORT_SCAN", "Full TCP/UDP port enumeration"),
        ("WEB_CRAWL", "Crawl web application endpoints"),
        ("VULNERABILITY_PROBE", "Active vulnerability detection"),
        ("FULL", "All scan types combined"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_priority(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("CRITICAL", "Highest priority — immediate queue"),
        ("HIGH", "High priority"),
        ("NORMAL", "Default priority"),
        ("LOW", "Background / off-peak"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_asset_type(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("HOST", "IP address or hostname"),
        ("DOMAIN", "Domain name"),
        ("URL", "URL endpoint"),
        ("ENDPOINT", "API endpoint"),
        ("CERTIFICATE", "TLS certificate"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_report_type(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("EXECUTIVE", "Executive summary for management"),
        ("TECHNICAL", "Detailed technical report"),
        ("EVIDENCE_EXPORT", "Raw evidence export"),
        ("REMEDIATION", "Remediation guidance"),
        ("COMPLIANCE", "Compliance mapping"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_report_format(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("JSON", "Machine-readable JSON"),
        ("HTML", "Web report"),
        ("PDF", "Portable Document Format"),
        ("CSV", "Comma-separated values"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.upper())]


def complete_output_format(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[tuple[str, str]]:
    choices = [
        ("table", "Rich formatted table (default)"),
        ("json", "JSON output"),
        ("yaml", "YAML output"),
        ("csv", "CSV output"),
    ]
    return [(v, d) for v, d in choices if v.startswith(incomplete.lower())]


def complete_context_name(
    ctx: Any,
    param: Any,
    incomplete: str,
) -> list[str]:
    try:
        from cves_cli.config.loader import load

        cfg = load()
        return [c.name for c in cfg.contexts if c.name.startswith(incomplete)]
    except Exception:
        return []
