"""Plugin management commands — list, run."""
from __future__ import annotations

import typer

from cves_cli.output.formatter import fmt

plugin_app = typer.Typer(name="plugin", help="Plugin management.", no_args_is_help=True)


@plugin_app.command("list")
def plugin_list() -> None:
    """List all installed CVEs CLI plugins."""
    from cves_cli.plugins.loader import get_plugin_info

    info = get_plugin_info()
    if not info:
        fmt.info("No plugins installed. Plugins are registered via the 'cves.plugins' entry-point group.")
        return
    fmt.print(info, title="Installed Plugins")


@plugin_app.command("run")
def plugin_run(
    name: str = typer.Argument(..., help="Plugin name."),
    args: list[str] = typer.Argument(None, help="Arguments passed to the plugin command."),
) -> None:
    """Run a specific plugin by name (delegates to its Typer sub-app)."""
    from cves_cli.plugins.loader import discover_plugins

    plugins = {p.name: p for p in discover_plugins()}
    if name not in plugins:
        fmt.error(f"Plugin '{name}' not found. Run: cves plugin list")
        raise typer.Exit(1)

    sub_app = plugins[name].get_commands()
    from click.testing import CliRunner

    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(sub_app, args or [], catch_exceptions=False)
    if result.output:
        typer.echo(result.output, nl=False)
    raise typer.Exit(result.exit_code)
