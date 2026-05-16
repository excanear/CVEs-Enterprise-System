"""Global application state — populated by root Typer callback."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cves_cli.config.models import CVEsConfig


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"


@dataclass
class AppState:
    profile: str = "default"
    output: OutputFormat = OutputFormat.TABLE
    quiet: bool = False
    no_header: bool = False
    ci: bool = False
    tenant_override: str | None = None

    # Populated lazily on first use
    _config: "CVEsConfig | None" = field(default=None, repr=False)

    def get_config(self) -> "CVEsConfig":
        if self._config is None:
            from cves_cli.config.loader import load

            self._config = load(self.profile)
        return self._config

    def invalidate_config(self) -> None:
        self._config = None

    def effective_tenant_id(self) -> str | None:
        """Return tenant_id: CLI override → context → auth entry."""
        if self.tenant_override:
            return self.tenant_override
        cfg = self.get_config()
        ctx = cfg.get_active_context()
        if ctx and ctx.tenant_id:
            return ctx.tenant_id
        ae = cfg.get_active_auth_entry()
        return ae.tenant_id if ae else None


# Module-level singleton — imported everywhere
app_state = AppState()
