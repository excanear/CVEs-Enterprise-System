"""Live telemetry dashboard — polls all 8 service health endpoints every 5s."""
from __future__ import annotations

import asyncio
import time
from typing import Any

import anyio
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, Static
from textual.widget import Widget

from cves_cli.config.models import ServiceEndpoints
from cves_cli.output.themes import status_badge, truncate_id
from cves_cli.tui.app import CVEsApp


_ALL_SERVICES = [
    ("scan_orchestrator", "Scan Orchestrator"),
    ("discovery_engine", "Discovery Engine"),
    ("asset_graph_engine", "Asset Graph Engine"),
    ("ai_correlation_layer", "AI Correlation Layer"),
    ("reporting_engine", "Reporting Engine"),
    ("runtime_analysis_engine", "Runtime Analysis"),
    ("js_intelligence_engine", "JS Intelligence"),
    ("exposure_validation_engine", "Exposure Validation"),
]


async def _ping(url: str, service_name: str) -> dict[str, Any]:
    import httpx

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url.rstrip("/") + "/health/ready")
            latency_ms = round((time.monotonic() - start) * 1000)
            if resp.status_code < 400:
                return {"service": service_name, "status": "HEALTHY", "latency_ms": latency_ms}
            return {"service": service_name, "status": "UNHEALTHY", "latency_ms": latency_ms}
    except Exception as exc:
        return {"service": service_name, "status": "UNHEALTHY", "latency_ms": -1, "error": str(exc)[:60]}


class TelemetryApp(CVEsApp):
    """Live dashboard showing health of all platform services."""

    TITLE = "CVEs Enterprise — Service Health"

    CSS = CVEsApp.CSS + """
    #summary {
        height: 3;
        content-align: center middle;
        color: $accent;
        text-style: bold;
    }
    #health-table {
        height: 1fr;
        border: round $primary;
        margin: 1;
    }
    """

    _results: reactive[list[dict]] = reactive([])

    def __init__(self, *, endpoints: ServiceEndpoints | None = None) -> None:
        super().__init__()
        self._endpoints = endpoints

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Loading…", id="summary")
        yield DataTable(id="health-table")
        yield Footer()

    def on_mount(self) -> None:
        table: DataTable = self.query_one("#health-table", DataTable)
        table.add_columns("Service", "Status", "Latency (ms)", "Notes")
        table.cursor_type = "none"
        self.run_worker(self._poll_loop(), exclusive=True, name="health-poller")

    async def _poll_loop(self) -> None:
        from cves_cli.state import app_state

        endpoints = self._endpoints
        if endpoints is None:
            endpoints = app_state.get_config().get_active_endpoints()

        ep_map: dict[str, str] = {
            "scan_orchestrator": endpoints.scan_orchestrator,
            "discovery_engine": endpoints.discovery_engine,
            "asset_graph_engine": endpoints.asset_graph_engine,
            "ai_correlation_layer": endpoints.ai_correlation_layer,
            "reporting_engine": endpoints.reporting_engine,
            "runtime_analysis_engine": endpoints.runtime_analysis_engine,
            "js_intelligence_engine": endpoints.js_intelligence_engine,
            "exposure_validation_engine": endpoints.exposure_validation_engine,
        }

        while True:
            tasks = [_ping(ep_map[key], label) for key, label in _ALL_SERVICES]
            results = list(await asyncio.gather(*tasks, return_exceptions=False))
            self.call_from_thread(self._update_table, results)
            await anyio.sleep(5)

    def _update_table(self, results: list[dict]) -> None:
        self._results = results
        table: DataTable = self.query_one("#health-table", DataTable)
        table.clear()

        healthy = sum(1 for r in results if r.get("status") == "HEALTHY")
        summary: Static = self.query_one("#summary", Static)
        color = "green" if healthy == len(results) else ("yellow" if healthy > 0 else "red")
        summary.update(f"[{color}]{healthy}/{len(results)} services healthy[/{color}]")

        for r in results:
            latency = r.get("latency_ms", -1)
            latency_str = f"{latency}ms" if latency >= 0 else "—"
            table.add_row(
                r.get("service", "—"),
                status_badge(r.get("status", "UNKNOWN")),
                Text(latency_str, justify="right"),
                r.get("error", ""),
            )

    def action_force_refresh(self) -> None:
        self.run_worker(self._poll_loop(), exclusive=True, name="health-poller")

    def action_export(self) -> None:
        import json
        from datetime import datetime

        path = f"health-{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
        with open(path, "w") as f:
            json.dump(self._results, f, indent=2, default=str)
        self.notify(f"Exported to {path}")
