"""Live scan watcher TUI — polls scan API every 2s and renders progress."""
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
from textual.worker import Worker, WorkerState

from cves_cli.config.models import ServiceEndpoints
from cves_cli.output.streaming import is_terminal
from cves_cli.output.themes import fmt_duration, status_badge, truncate_id
from cves_cli.tui.app import CVEsApp


class ScanWatchApp(CVEsApp):
    """Full-terminal scan watcher — updates every 2 seconds."""

    TITLE = "CVEs Enterprise — Scan Watcher"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "force_refresh", "Refresh"),
        Binding("e", "export", "Export JSON"),
    ]

    CSS = CVEsApp.CSS + """
    #scan-meta {
        width: 1fr;
        height: 100%;
        border: round $primary;
        padding: 1;
    }
    #task-panel {
        width: 2fr;
        height: 100%;
        border: round $primary;
        padding: 1;
    }
    #status-bar {
        height: 3;
        dock: bottom;
    }
    """

    scan_status: reactive[str] = reactive("PENDING")
    tasks_completed: reactive[int] = reactive(0)
    tasks_total: reactive[int] = reactive(0)

    def __init__(
        self,
        *,
        scan_id: str,
        auth_name: str = "default",
        auth_type: str = "api_key",
        tenant_id: str | None = None,
        endpoints: ServiceEndpoints | None = None,
    ) -> None:
        super().__init__()
        self._scan_id = scan_id
        self._auth_name = auth_name
        self._auth_type = auth_type
        self._tenant_id = tenant_id
        self._endpoints = endpoints
        self._last_data: dict = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="scan-meta"):
                yield Label("[bold cyan]Scan Details[/bold cyan]")
                yield DataTable(id="meta-table", show_header=False)
            with Vertical(id="task-panel"):
                yield Label("[bold cyan]Tasks[/bold cyan]")
                yield DataTable(id="task-table")
        yield ProgressBar(id="progress-bar", total=100, show_eta=False)
        yield Footer()

    def on_mount(self) -> None:
        meta: DataTable = self.query_one("#meta-table", DataTable)
        meta.add_columns("Key", "Value")
        meta.cursor_type = "none"

        task_table: DataTable = self.query_one("#task-table", DataTable)
        task_table.add_columns("Task ID", "Type", "Target", "Status", "Attempt", "Error")

        self._start_worker()

    def _start_worker(self) -> None:
        self.run_worker(self._poll_loop(), exclusive=True, name="poller")

    async def _poll_loop(self) -> None:
        from cves_cli.client.base import build_client
        from cves_cli.client.scan import ScanClient
        from cves_cli.state import app_state

        endpoints = self._endpoints
        if endpoints is None:
            endpoints = app_state.get_config().get_active_endpoints()

        while True:
            try:
                async with build_client(
                    endpoints.scan_orchestrator,
                    auth_name=self._auth_name,
                    auth_type=self._auth_type,
                    tenant_id=self._tenant_id,
                ) as http:
                    data = await ScanClient(http).get(self._scan_id)

                self._last_data = data
                self.call_from_thread(self._update_ui, data)

                status = data.get("scan_status", data.get("status", "UNKNOWN"))
                if is_terminal(status):
                    await anyio.sleep(0.5)
                    self.call_from_thread(self.exit)
                    return
            except Exception as exc:
                self.call_from_thread(self._show_error, str(exc))

            await anyio.sleep(2)

    def _update_ui(self, data: dict) -> None:
        status = data.get("scan_status", data.get("status", "UNKNOWN"))
        self.scan_status = status

        # Meta table
        meta: DataTable = self.query_one("#meta-table", DataTable)
        meta.clear()
        rows = [
            ("Scan ID", self._scan_id),
            ("Type", data.get("scan_type", "—")),
            ("Status", status),
            ("Priority", data.get("priority", "—")),
            ("Initiated By", data.get("initiated_by", "—")),
            ("Duration", fmt_duration(data.get("duration_seconds"))),
        ]
        for key, val in rows:
            meta.add_row(Text(key, style="bold"), str(val))

        # Tasks table
        tasks = data.get("tasks", [])
        self.tasks_completed = sum(1 for t in tasks if is_terminal(t.get("status", "")))
        self.tasks_total = len(tasks)

        task_table: DataTable = self.query_one("#task-table", DataTable)
        task_table.clear()
        for task in tasks:
            task_table.add_row(
                truncate_id(str(task.get("task_id", task.get("id", "")))),
                task.get("task_type", task.get("type", "—")),
                str(task.get("target", "—"))[:40],
                status_badge(task.get("status", "")),
                str(task.get("attempt", 1)),
                str(task.get("error", "—"))[:30],
            )

        # Progress bar
        bar: ProgressBar = self.query_one("#progress-bar", ProgressBar)
        if self.tasks_total:
            pct = int(self.tasks_completed / self.tasks_total * 100)
            bar.update(progress=pct)

        self.title = f"Scan {truncate_id(self._scan_id)} — {status}"

    def _show_error(self, message: str) -> None:
        self.notify(f"Error: {message}", severity="error")

    def action_force_refresh(self) -> None:
        self.run_worker(self._poll_loop(), exclusive=True, name="poller")

    def action_export(self) -> None:
        if self._last_data:
            path = f"scan-{self._scan_id[:8]}-{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
            with open(path, "w") as f:
                json.dump(self._last_data, f, indent=2, default=str)
            self.notify(f"Exported to {path}")
