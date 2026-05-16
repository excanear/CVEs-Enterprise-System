"""Scan commands — submit, list, get, cancel, retry, watch, schedule."""
from __future__ import annotations

from typing import List, Optional

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import scan_table, schedule_job_table, worker_pool_table

scan_app = typer.Typer(name="scan", help="Scan lifecycle management.", no_args_is_help=True)
schedule_app = typer.Typer(name="schedule", help="Scheduled scan jobs.", no_args_is_help=True)
scan_app.add_typer(schedule_app)


@scan_app.command("submit")
def scan_submit(
    scan_type: str = typer.Option("FULL", "--type", "-t", help="NETWORK_DISCOVERY | PORT_SCAN | WEB_CRAWL | VULNERABILITY_PROBE | FULL"),
    targets: List[str] = typer.Option(..., "--target", "-T", help="Target(s). Repeat for multiple."),
    priority: str = typer.Option("NORMAL", "--priority", "-p", help="CRITICAL | HIGH | NORMAL | LOW"),
    wait: bool = typer.Option(False, "--wait", "-w", help="Wait for scan to finish."),
    no_tui: bool = typer.Option(False, "--no-tui", help="Use Rich progress instead of Textual TUI."),
    timeout: int = typer.Option(3600, "--timeout", help="Max seconds to wait (with --wait)."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if status matches (e.g. FAILED)."),
) -> None:
    """Submit a new scan and optionally watch it to completion."""
    from cves_cli.client.factory import scan_client
    from cves_cli.output.streaming import poll_until_terminal, RichLivePoller, is_terminal
    from cves_cli.state import app_state
    from cves_cli.tui.scan_watch import ScanWatchApp

    async def _submit() -> dict:
        async with scan_client() as c:
            return await c.submit(scan_type=scan_type, targets=list(targets), priority=priority)

    result = anyio.run(_submit)
    scan_id = result.get("scan_id", result.get("id", ""))
    fmt.success(f"Scan submitted: {scan_id}")
    fmt.print(result, title="Scan")

    if not wait:
        return

    if not no_tui and not app_state.ci:
        cfg = app_state.get_config()
        ae = cfg.get_active_auth_entry()
        ScanWatchApp(
            scan_id=scan_id,
            auth_name=ae.name if ae else "default",
            auth_type=ae.type if ae else "api_key",
            tenant_id=app_state.effective_tenant_id(),
            endpoints=cfg.get_active_endpoints(),
        ).run()
        return

    # --no-tui or --ci: use Rich Live poller
    async def _poll() -> dict:
        with RichLivePoller(f"Watching scan {scan_id[:8]}…") as poller:
            async def fetch() -> dict:
                async with scan_client() as c:
                    return await c.get(scan_id)

            def on_update(data: dict) -> None:
                s = data.get("scan_status", data.get("status", "?"))
                done = data.get("tasks_completed", 0)
                total = data.get("tasks_total", 0)
                pct = f"{done}/{total}" if total else "—"
                poller.update(f"[cyan]{scan_id[:8]}[/cyan] {s} ({pct})")

            return await poll_until_terminal(fetch, interval=3, timeout=timeout, on_update=on_update)

    final = anyio.run(_poll)
    final_status = final.get("scan_status", final.get("status", ""))
    fmt.print(final, title="Final Scan State")

    if fail_on and final_status.upper() == fail_on.upper():
        raise typer.Exit(1)


@scan_app.command("list")
def scan_list(
    status: str = typer.Option("RUNNING", "--status", "-s"),
    limit: int = typer.Option(50, "--limit", "-n"),
) -> None:
    """List scans."""
    from cves_cli.client.factory import scan_client

    async def _list() -> list:
        async with scan_client() as c:
            return await c.list(status=status, limit=limit)

    rows = anyio.run(_list)
    fmt.print(rows, table_factory=scan_table, title=f"Scans [{status}]")


@scan_app.command("get")
def scan_get(
    scan_id: str = typer.Argument(..., help="Scan ID."),
) -> None:
    """Get details for a specific scan."""
    from cves_cli.client.factory import scan_client

    async def _get() -> dict:
        async with scan_client() as c:
            return await c.get(scan_id)

    result = anyio.run(_get)
    fmt.print(result, table_factory=lambda d: scan_table([d]))


@scan_app.command("cancel")
def scan_cancel(
    scan_id: str = typer.Argument(...),
    confirm: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Cancel a running scan."""
    from cves_cli.client.factory import scan_client

    if not confirm:
        typer.confirm(f"Cancel scan {scan_id}?", abort=True)

    async def _cancel() -> None:
        async with scan_client() as c:
            await c.cancel(scan_id)

    anyio.run(_cancel)
    fmt.success(f"Scan {scan_id} cancelled.")


@scan_app.command("retry")
def scan_retry(
    scan_id: str = typer.Argument(...),
) -> None:
    """Retry failed tasks in a scan."""
    from cves_cli.client.factory import scan_client

    async def _retry() -> dict:
        async with scan_client() as c:
            return await c.retry(scan_id)

    result = anyio.run(_retry)
    fmt.success(f"Retry triggered for scan {scan_id}.")
    fmt.print(result)


@scan_app.command("watch")
def scan_watch(
    scan_id: str = typer.Argument(...),
) -> None:
    """Open live TUI watcher for a scan."""
    from cves_cli.state import app_state
    from cves_cli.tui.scan_watch import ScanWatchApp

    cfg = app_state.get_config()
    ae = cfg.get_active_auth_entry()
    ScanWatchApp(
        scan_id=scan_id,
        auth_name=ae.name if ae else "default",
        auth_type=ae.type if ae else "api_key",
        tenant_id=app_state.effective_tenant_id(),
        endpoints=cfg.get_active_endpoints(),
    ).run()


# ── Schedule sub-commands ────────────────────────────────────────────────────

@schedule_app.command("list")
def schedule_list() -> None:
    """List scheduled scan jobs."""
    from cves_cli.client.factory import scan_client

    async def _list() -> list:
        async with scan_client() as c:
            return await c.list_jobs()

    rows = anyio.run(_list)
    fmt.print(rows, table_factory=schedule_job_table, title="Scheduled Jobs")


@schedule_app.command("create")
def schedule_create(
    name: str = typer.Option(..., "--name", "-n"),
    cron: str = typer.Option(..., "--cron", "-c", help="Cron expression, e.g. '0 2 * * *'"),
    scan_type: str = typer.Option("FULL", "--type", "-t"),
    targets: List[str] = typer.Option(..., "--target", "-T"),
    priority: str = typer.Option("NORMAL", "--priority", "-p"),
) -> None:
    """Create a scheduled scan job."""
    from cves_cli.client.factory import scan_client

    async def _create() -> dict:
        async with scan_client() as c:
            return await c.create_job(
                name=name,
                cron_expression=cron,
                scan_type=scan_type,
                targets=list(targets),
                priority=priority,
            )

    result = anyio.run(_create)
    fmt.success(f"Scheduled job created: {result.get('job_id', result.get('id', ''))}")
    fmt.print(result)


@schedule_app.command("delete")
def schedule_delete(
    job_id: str = typer.Argument(...),
    confirm: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Delete a scheduled job."""
    from cves_cli.client.factory import scan_client

    if not confirm:
        typer.confirm(f"Delete scheduled job {job_id}?", abort=True)

    async def _delete() -> None:
        async with scan_client() as c:
            await c.delete_job(job_id)

    anyio.run(_delete)
    fmt.success(f"Scheduled job {job_id} deleted.")
