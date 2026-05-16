"""Health commands — check service health, launch live telemetry dashboard."""
from __future__ import annotations

import asyncio
import time
from typing import Optional

import anyio
import httpx
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import health_table

health_app = typer.Typer(name="health", help="Service health monitoring.", no_args_is_help=True)

_SERVICE_NAMES = [
    "scan_orchestrator",
    "discovery_engine",
    "asset_graph_engine",
    "ai_correlation_layer",
    "reporting_engine",
    "runtime_analysis_engine",
    "js_intelligence_engine",
    "exposure_validation_engine",
]


async def _ping_one(name: str, url: str) -> dict:
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url.rstrip("/") + "/health/ready")
            latency = round((time.monotonic() - start) * 1000)
            status = "HEALTHY" if resp.status_code < 400 else "UNHEALTHY"
            return {"service": name, "status": status, "latency_ms": latency, "checked_at": "now"}
    except Exception as exc:
        return {"service": name, "status": "UNHEALTHY", "latency_ms": -1, "error": str(exc)[:80]}


@health_app.command("check")
def health_check(
    service: Optional[str] = typer.Argument(None, help="Specific service name (or 'all')."),
    fail_if_unhealthy: bool = typer.Option(False, "--fail", "-f", help="Exit 1 if any service is unhealthy."),
) -> None:
    """Check health of platform services."""
    from cves_cli.state import app_state

    ep = app_state.get_config().get_active_endpoints()
    ep_map = {
        "scan_orchestrator": ep.scan_orchestrator,
        "discovery_engine": ep.discovery_engine,
        "asset_graph_engine": ep.asset_graph_engine,
        "ai_correlation_layer": ep.ai_correlation_layer,
        "reporting_engine": ep.reporting_engine,
        "runtime_analysis_engine": ep.runtime_analysis_engine,
        "js_intelligence_engine": ep.js_intelligence_engine,
        "exposure_validation_engine": ep.exposure_validation_engine,
    }

    if service and service != "all" and service in ep_map:
        targets = {service: ep_map[service]}
    else:
        targets = ep_map

    async def _check() -> list:
        tasks = [_ping_one(name, url) for name, url in targets.items()]
        return list(await asyncio.gather(*tasks))

    results = anyio.run(_check)
    fmt.print(results, table_factory=health_table, title="Service Health")

    if fail_if_unhealthy and any(r["status"] != "HEALTHY" for r in results):
        raise typer.Exit(1)


@health_app.command("watch")
def health_watch() -> None:
    """Open live telemetry dashboard (Textual TUI)."""
    from cves_cli.state import app_state
    from cves_cli.tui.telemetry import TelemetryApp

    ep = app_state.get_config().get_active_endpoints()
    TelemetryApp(endpoints=ep).run()
