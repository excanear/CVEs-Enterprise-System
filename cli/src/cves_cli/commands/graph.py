"""Graph commands — assets, attack-paths, trust-chains, propagation, stats."""
from __future__ import annotations

from typing import Optional

import anyio
import typer

from cves_cli.output.formatter import fmt
from cves_cli.output.tables import asset_table, attack_path_table

graph_app = typer.Typer(name="graph", help="Asset relationship graph.", no_args_is_help=True)


def _tenant(ctx_tenant: Optional[str]) -> str:
    from cves_cli.state import app_state

    return ctx_tenant or app_state.effective_tenant_id() or ""


@graph_app.command("assets")
def graph_assets(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    limit: int = typer.Option(100, "--limit", "-n"),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    """List all assets in the graph."""
    from cves_cli.client.factory import graph_client

    async def _get() -> list:
        async with graph_client() as c:
            return await c.list_assets(tenant_id=_tenant(tenant), limit=limit, offset=offset)

    rows = anyio.run(_get)
    fmt.print(rows, table_factory=asset_table, title="Graph Assets")


@graph_app.command("attack-paths")
def graph_attack_paths(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    max_paths: int = typer.Option(20, "--max"),
) -> None:
    """Show ranked attack paths."""
    from cves_cli.client.factory import graph_client

    async def _get() -> list:
        async with graph_client() as c:
            return await c.attack_paths(tenant_id=_tenant(tenant), max_paths=max_paths)

    rows = anyio.run(_get)
    fmt.print(rows, table_factory=attack_path_table, title="Attack Paths")


@graph_app.command("trust-chains")
def graph_trust_chains(
    asset_id: str = typer.Argument(...),
    tenant: Optional[str] = typer.Option(None, "--tenant"),
    depth: int = typer.Option(10, "--depth"),
) -> None:
    """Show trust chains from a root asset."""
    from cves_cli.client.factory import graph_client

    async def _get() -> list:
        async with graph_client() as c:
            return await c.trust_chains(tenant_id=_tenant(tenant), asset_id=asset_id, max_depth=depth)

    rows = anyio.run(_get)
    fmt.print(rows, title=f"Trust Chains [{asset_id[:8]}]")


@graph_app.command("propagation")
def graph_propagation(
    endpoint_id: str = typer.Argument(...),
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show exposure propagation from an endpoint."""
    from cves_cli.client.factory import graph_client

    async def _get() -> list:
        async with graph_client() as c:
            return await c.propagation(tenant_id=_tenant(tenant), endpoint_id=endpoint_id)

    rows = anyio.run(_get)
    fmt.print(rows, title=f"Propagation [{endpoint_id[:8]}]")


@graph_app.command("stats")
def graph_stats(
    tenant: Optional[str] = typer.Option(None, "--tenant"),
) -> None:
    """Show graph statistics for the tenant."""
    from cves_cli.client.factory import graph_client

    async def _get() -> dict:
        async with graph_client() as c:
            return await c.stats(tenant_id=_tenant(tenant))

    data = anyio.run(_get)
    fmt.print(data, title="Graph Statistics")
