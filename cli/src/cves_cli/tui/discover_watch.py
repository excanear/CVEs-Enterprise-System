"""Discovery job watcher TUI — similar to ScanWatchApp."""
from __future__ import annotations

import json
from datetime import datetime

import anyio
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, ProgressBar

from cves_cli.config.models import ServiceEndpoints
from cves_cli.output.streaming import is_terminal
from cves_cli.output.themes import fmt_duration, status_badge, truncate_id
from cves_cli.tui.app import CVEsApp


class DiscoverWatchApp(CVEsApp):
    """Full-terminal discovery job watcher."""

    TITLE = "CVEs Enterprise — Discovery Watcher"

    CSS = CVEsApp.CSS + """
    #job-meta {
        width: 1fr;
        height: 100%;
        border: round $primary;
        padding: 1;
    }
    #asset-panel {
        width: 2fr;
        height: 100%;
        border: round $primary;
        padding: 1;
    }
    """

    def __init__(
        self,
        *,
        job_id: str,
        auth_name: str = "default",
        auth_type: str = "api_key",
        tenant_id: str | None = None,
        endpoints: ServiceEndpoints | None = None,
    ) -> None:
        super().__init__()
        self._job_id = job_id
        self._auth_name = auth_name
        self._auth_type = auth_type
        self._tenant_id = tenant_id
        self._endpoints = endpoints
        self._last_data: dict = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="job-meta"):
                yield Label("[bold cyan]Discovery Job[/bold cyan]")
                yield DataTable(id="meta-table", show_header=False)
            with Vertical(id="asset-panel"):
                yield Label("[bold cyan]Discovered Assets[/bold cyan]")
                yield DataTable(id="asset-table")
        yield Footer()

    def on_mount(self) -> None:
        meta: DataTable = self.query_one("#meta-table", DataTable)
        meta.add_columns("Key", "Value")
        meta.cursor_type = "none"

        asset_table: DataTable = self.query_one("#asset-table", DataTable)
        asset_table.add_columns("Asset ID", "Type", "Value", "Status", "Source")

        self.run_worker(self._poll_loop(), exclusive=True, name="discover-poller")

    async def _poll_loop(self) -> None:
        from cves_cli.client.base import build_client
        from cves_cli.client.discovery import DiscoveryClient
        from cves_cli.state import app_state

        endpoints = self._endpoints
        if endpoints is None:
            endpoints = app_state.get_config().get_active_endpoints()

        while True:
            try:
                async with build_client(
                    endpoints.discovery_engine,
                    auth_name=self._auth_name,
                    auth_type=self._auth_type,
                    tenant_id=self._tenant_id,
                ) as http:
                    data = await DiscoveryClient(http).get_job(self._job_id)
                    assets = await DiscoveryClient(http).job_assets(self._job_id)

                self._last_data = {**data, "assets": assets}
                self.call_from_thread(self._update_ui, data, assets)

                status = data.get("status", "UNKNOWN")
                if is_terminal(status):
                    await anyio.sleep(0.5)
                    self.call_from_thread(self.exit)
                    return
            except Exception as exc:
                self.call_from_thread(self._show_error, str(exc))

            await anyio.sleep(2)

    def _update_ui(self, data: dict, assets: list) -> None:
        status = data.get("status", "UNKNOWN")

        # Meta table
        meta: DataTable = self.query_one("#meta-table", DataTable)
        meta.clear()
        rows = [
            ("Job ID", self._job_id),
            ("Target", data.get("target_domain", data.get("target_url", "—"))),
            ("Status", status),
            ("Assets Found", str(data.get("assets_found", data.get("assets_discovered", "—")))),
            ("Endpoints", str(data.get("endpoints_found", "—"))),
            ("Duration", fmt_duration(data.get("duration_seconds"))),
        ]
        for key, val in rows:
            meta.add_row(Text(key, style="bold"), str(val))

        # Asset table
        asset_table: DataTable = self.query_one("#asset-table", DataTable)
        asset_table.clear()
        for asset in (assets or [])[:200]:
            asset_table.add_row(
                truncate_id(str(asset.get("asset_id", asset.get("id", "")))),
                asset.get("asset_type", asset.get("type", "—")),
                str(asset.get("value", asset.get("url", asset.get("domain", "—"))))[:50],
                status_badge(asset.get("status", "UNKNOWN")),
                asset.get("source", "—"),
            )

        self.title = f"Discovery {truncate_id(self._job_id)} — {status}"

    def _show_error(self, message: str) -> None:
        self.notify(f"Error: {message}", severity="error")

    def action_force_refresh(self) -> None:
        self.run_worker(self._poll_loop(), exclusive=True, name="discover-poller")

    def action_export(self) -> None:
        if self._last_data:
            path = f"discovery-{self._job_id[:8]}-{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
            with open(path, "w") as f:
                json.dump(self._last_data, f, indent=2, default=str)
            self.notify(f"Exported to {path}")
