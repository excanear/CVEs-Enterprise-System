"""Workers commands — pool stats, heartbeats."""
from __future__ import annotations

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import worker_pool_table

workers_app = typer.Typer(name="workers", help="Scan worker pool management.", no_args_is_help=True)


@workers_app.command("pools")
def workers_pools() -> None:
    """Show worker pool status and capacity."""
    from cves_cli.client.factory import scan_client

    async def _get() -> dict:
        async with scan_client() as c:
            return await c.worker_pools()

    data = anyio.run(_get)
    pools = data if isinstance(data, list) else data.get("pools", [data])
    fmt.print(pools, table_factory=worker_pool_table, title="Worker Pools")


@workers_app.command("heartbeats")
def workers_heartbeats() -> None:
    """Show recent worker heartbeats."""
    from cves_cli.client.factory import scan_client

    async def _get() -> dict:
        async with scan_client() as c:
            return await c.worker_heartbeats()

    data = anyio.run(_get)
    fmt.print(data, title="Worker Heartbeats")


@workers_app.command("queue")
def workers_queue() -> None:
    """Show current scan queue depth."""
    from cves_cli.client.factory import scan_client

    async def _get() -> dict:
        async with scan_client() as c:
            return await c.queue_depth()

    data = anyio.run(_get)
    fmt.print(data, title="Queue Depth")
