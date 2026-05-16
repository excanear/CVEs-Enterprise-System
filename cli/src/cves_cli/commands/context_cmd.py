"""Context management commands — list, use, show, set."""
from __future__ import annotations

import typer

from cves_cli.output.formatter import fmt

context_app = typer.Typer(name="context", help="Manage CLI contexts (cluster + auth).", no_args_is_help=True)


@context_app.command("list")
def ctx_list() -> None:
    """List all configured contexts."""
    from cves_cli.config.loader import load

    cfg = load()
    rows = [
        {
            "name": c.name,
            "cluster": c.cluster,
            "auth": c.auth,
            "current": "✓" if c.name == cfg.current_context else "",
        }
        for c in cfg.contexts
    ]
    fmt.print(rows, title="Contexts")


@context_app.command("use")
def ctx_use(
    name: str = typer.Argument(..., help="Context name to activate."),
) -> None:
    """Switch the active context."""
    from cves_cli.config.loader import set_current_context

    set_current_context(name)
    fmt.success(f"Switched to context '{name}'.")


@context_app.command("show")
def ctx_show() -> None:
    """Show the full active context configuration."""
    from cves_cli.config.loader import load

    cfg = load()
    ctx = cfg.get_active_context()
    if ctx is None:
        fmt.error("No active context. Run: cves context use <name>")
        raise typer.Exit(1)

    cluster = cfg.get_active_cluster()
    auth_entry = cfg.get_active_auth_entry()

    data = {
        "context": ctx.model_dump(),
        "cluster": cluster.model_dump() if cluster else None,
        "auth": auth_entry.model_dump(exclude={"client_secret"}) if auth_entry else None,
        "endpoints": cfg.get_active_endpoints().model_dump() if cluster else None,
    }
    fmt.print(data, title=f"Context: {ctx.name}")


@context_app.command("set")
def ctx_set(
    key: str = typer.Argument(..., help="Dot-path key, e.g. cluster.scan_orchestrator"),
    value: str = typer.Argument(..., help="New value."),
) -> None:
    """Set a configuration value in the active context or cluster."""
    from cves_cli.config.loader import load, save

    cfg = load()
    ctx = cfg.get_active_context()
    if ctx is None:
        fmt.error("No active context.")
        raise typer.Exit(1)

    parts = key.split(".")
    if parts[0] == "cluster" and len(parts) == 2:
        cluster = cfg.get_active_cluster()
        if cluster and hasattr(cluster.endpoints, parts[1]):
            setattr(cluster.endpoints, parts[1], value)
            cfg.upsert_cluster(cluster)
            save(cfg)
            fmt.success(f"Set cluster.endpoints.{parts[1]} = {value}")
            return
    elif parts[0] == "auth" and len(parts) == 2:
        ae = cfg.get_active_auth_entry()
        if ae and hasattr(ae, parts[1]):
            setattr(ae, parts[1], value)
            cfg.upsert_auth_entry(ae)
            save(cfg)
            fmt.success(f"Set auth.{parts[1]} = {value}")
            return
    elif len(parts) == 1:
        if hasattr(ctx, parts[0]):
            setattr(ctx, parts[0], value)
            cfg.upsert_context(ctx)
            save(cfg)
            fmt.success(f"Set context.{parts[0]} = {value}")
            return

    fmt.error(f"Unknown key path: {key}")
    raise typer.Exit(1)
