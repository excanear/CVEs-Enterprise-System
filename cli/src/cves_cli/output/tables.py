"""Pre-built Rich Table factories for every domain object."""
from __future__ import annotations

from typing import Any

from rich.table import Table
from rich.text import Text

from cves_cli.output.themes import fmt_duration, fmt_pct, status_badge, tier_badge, truncate_id


def _base_table(*headers: tuple[str, str | None, str]) -> Table:
    """Create a styled Rich table.

    headers: list of (column_name, style, justify)
    """
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=False)
    return t


def scan_table(scans: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("ID", style="dim", no_wrap=True)
    t.add_column("Type")
    t.add_column("Status")
    t.add_column("Priority", justify="right")
    t.add_column("Progress", justify="right")
    t.add_column("Tasks", justify="right")
    t.add_column("Initiated By")
    t.add_column("Duration", justify="right")

    for s in scans:
        tasks_completed = s.get("tasks_completed", 0)
        tasks_total = s.get("tasks_total", 0)
        progress = (tasks_completed / tasks_total * 100) if tasks_total else 0

        t.add_row(
            truncate_id(s.get("scan_id", s.get("id", ""))),
            s.get("scan_type", "—"),
            status_badge(s.get("scan_status", s.get("status", ""))),
            s.get("priority", "—"),
            fmt_pct(progress),
            f"{tasks_completed}/{tasks_total}" if tasks_total else "—",
            s.get("initiated_by", "—"),
            fmt_duration(s.get("duration_seconds")),
        )
    return t


def asset_table(assets: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("ID", style="dim", no_wrap=True)
    t.add_column("Type")
    t.add_column("Value", max_width=60)
    t.add_column("Status")
    t.add_column("Confidence", justify="right")
    t.add_column("Source")

    for a in assets:
        t.add_row(
            truncate_id(str(a.get("asset_id", a.get("id", "")))),
            a.get("asset_type", a.get("type", "—")),
            str(a.get("value", a.get("url", a.get("domain", "—")))),
            status_badge(a.get("status", "UNKNOWN")),
            fmt_pct(float(a.get("confidence", 0)) * 100 if a.get("confidence") else None),
            a.get("source", "—"),
        )
    return t


def job_table(jobs: list[dict[str, Any]], *, domain_key: str = "target_domain") -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("ID", style="dim", no_wrap=True)
    t.add_column("Target", max_width=50)
    t.add_column("Status")
    t.add_column("Assets", justify="right")
    t.add_column("Endpoints", justify="right")
    t.add_column("Duration", justify="right")

    for j in jobs:
        t.add_row(
            truncate_id(str(j.get("job_id", j.get("id", "")))),
            str(j.get(domain_key, j.get("target_url", "—"))),
            status_badge(j.get("status", "")),
            str(j.get("assets_found", j.get("assets_discovered", "—"))),
            str(j.get("endpoints_found", "—")),
            fmt_duration(j.get("duration_seconds")),
        )
    return t


def cluster_table(clusters: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("Cluster ID", style="dim", no_wrap=True)
    t.add_column("Risk Tier")
    t.add_column("Size", justify="right")
    t.add_column("Host")
    t.add_column("Avg Score", justify="right")

    for c in clusters:
        t.add_row(
            truncate_id(str(c.get("cluster_id", c.get("id", "")))),
            tier_badge(c.get("risk_tier", c.get("tier", ""))),
            str(c.get("size", "—")),
            str(c.get("representative_host", c.get("host", "—"))),
            f"{c.get('avg_confidence', c.get('score', 0)):.2f}" if c.get("avg_confidence") or c.get("score") else "—",
        )
    return t


def attack_path_table(paths: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("#", justify="right")
    t.add_column("Source", max_width=40)
    t.add_column("Target", max_width=40)
    t.add_column("Hops", justify="right")
    t.add_column("Risk Score", justify="right")
    t.add_column("Composite", justify="right")

    for i, p in enumerate(paths, 1):
        t.add_row(
            str(i),
            str(p.get("source", p.get("start_node", "—"))),
            str(p.get("target", p.get("end_node", "—"))),
            str(p.get("hops", p.get("path_length", "—"))),
            f"{p.get('risk_score', 0):.2f}" if p.get("risk_score") is not None else "—",
            f"{p.get('composite_score', 0):.2f}" if p.get("composite_score") is not None else "—",
        )
    return t


def report_table(reports: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("Report ID", style="dim", no_wrap=True)
    t.add_column("Type")
    t.add_column("Format")
    t.add_column("Status")
    t.add_column("Findings", justify="right")
    t.add_column("Created At")

    for r in reports:
        t.add_row(
            truncate_id(str(r.get("report_id", r.get("id", "")))),
            r.get("report_type", r.get("type", "—")),
            r.get("report_format", r.get("format", "—")),
            status_badge(r.get("status", "")),
            str(r.get("finding_count", r.get("findings", "—"))),
            str(r.get("created_at", "—")),
        )
    return t


def health_table(results: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("Service")
    t.add_column("Status")
    t.add_column("Latency (ms)", justify="right")
    t.add_column("Checked At")

    for r in results:
        t.add_row(
            r.get("service", "—"),
            status_badge(r.get("status", "UNKNOWN")),
            f"{r.get('latency_ms', '—')}",
            str(r.get("checked_at", "—")),
        )
    return t


def worker_pool_table(pools: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("Pool ID", style="dim", no_wrap=True)
    t.add_column("Status")
    t.add_column("Active Workers", justify="right")
    t.add_column("Capacity", justify="right")
    t.add_column("Queue Depth", justify="right")

    for p in pools:
        t.add_row(
            truncate_id(str(p.get("pool_id", p.get("id", "")))),
            status_badge(p.get("status", "")),
            str(p.get("active_workers", "—")),
            str(p.get("capacity", "—")),
            str(p.get("queue_depth", "—")),
        )
    return t


def schedule_job_table(jobs: list[dict[str, Any]]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", box=None, expand=True)
    t.add_column("Job ID", style="dim", no_wrap=True)
    t.add_column("Name")
    t.add_column("Cron")
    t.add_column("Type")
    t.add_column("Status")
    t.add_column("Next Run")

    for j in jobs:
        t.add_row(
            truncate_id(str(j.get("job_id", j.get("id", "")))),
            str(j.get("name", "—")),
            str(j.get("cron_expression", j.get("cron", "—"))),
            str(j.get("scan_type", j.get("type", "—"))),
            status_badge(j.get("status", "ACTIVE")),
            str(j.get("next_run", "—")),
        )
    return t
