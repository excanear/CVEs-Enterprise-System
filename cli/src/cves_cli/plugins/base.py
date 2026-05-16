"""Plugin base class — all third-party CVEs CLI plugins must subclass CVEsPlugin."""
from __future__ import annotations

from abc import ABC, abstractmethod

import typer

from cves_cli.state import AppState


class CVEsPlugin(ABC):
    """Contract for CVEs CLI plugins registered under `cves.plugins` entry point."""

    #: Short unique name used as the Typer sub-command name.
    name: str
    #: SemVer version string.
    version: str = "0.0.0"
    #: Human-readable description shown in `cves plugin list`.
    description: str = ""

    @abstractmethod
    def get_commands(self) -> typer.Typer:
        """Return a Typer sub-app whose commands this plugin contributes."""
        ...

    def on_load(self, state: AppState) -> None:  # noqa: B027 (intentionally empty)
        """Called after the plugin is loaded. Override for initialization."""
