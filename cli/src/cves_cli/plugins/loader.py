"""Plugin discovery and registration via importlib.metadata entry points."""
from __future__ import annotations

import importlib.metadata
import warnings

import typer

from cves_cli.plugins.base import CVEsPlugin
from cves_cli.state import app_state


def discover_plugins() -> list[CVEsPlugin]:
    """Load all plugins registered under the `cves.plugins` entry-point group."""
    plugins: list[CVEsPlugin] = []
    try:
        eps = importlib.metadata.entry_points(group="cves.plugins")
    except Exception:
        return plugins

    for ep in eps:
        try:
            cls = ep.load()
            if not (isinstance(cls, type) and issubclass(cls, CVEsPlugin)):
                warnings.warn(f"Plugin {ep.name!r} does not subclass CVEsPlugin — skipped.", stacklevel=1)
                continue
            instance: CVEsPlugin = cls()
            instance.on_load(app_state)
            plugins.append(instance)
        except Exception as exc:
            warnings.warn(f"Failed to load plugin {ep.name!r}: {exc}", stacklevel=1)

    return plugins


def register_plugins(app: typer.Typer, plugins: list[CVEsPlugin]) -> None:
    """Attach each plugin's Typer sub-app to the root app."""
    for plugin in plugins:
        try:
            sub = plugin.get_commands()
            app.add_typer(sub, name=plugin.name)
        except Exception as exc:
            warnings.warn(f"Failed to register plugin {plugin.name!r}: {exc}", stacklevel=1)


def get_plugin_info() -> list[dict]:
    """Return metadata for all loaded plugins (used by `cves plugin list`)."""
    plugins = discover_plugins()
    return [
        {
            "name": p.name,
            "version": p.version,
            "description": p.description,
            "entry_point": type(p).__module__ + "." + type(p).__qualname__,
        }
        for p in plugins
    ]
