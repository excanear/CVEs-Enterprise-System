"""Config file loader — ~/.config/cves/config.yaml.

Precedence (highest wins):
  1. Environment variables (CVES_CONTEXT, CVES_CLUSTER_*, CVES_API_KEY, ...)
  2. Active profile / context in config file
  3. Built-in defaults (localhost endpoints)
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from cves_cli.config.models import (
    AuthEntry,
    Cluster,
    Context,
    CVEsConfig,
    ServiceEndpoints,
)

_CONFIG_DIR = Path(os.environ.get("CVES_CONFIG_DIR", Path.home() / ".config" / "cves"))
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"


def config_path() -> Path:
    return _CONFIG_FILE


def _ensure_default_config(cfg: CVEsConfig) -> CVEsConfig:
    """Inject a 'default' context pointing to localhost if none exist."""
    if not cfg.clusters:
        cfg.clusters.append(Cluster(name="local"))
    if not cfg.auth_entries:
        # Check env var for bootstrap key
        api_key = os.environ.get("CVES_API_KEY")
        tenant_id = os.environ.get("CVES_TENANT_ID")
        cfg.auth_entries.append(
            AuthEntry(
                name="default",
                type="api_key" if api_key else "token",
                tenant_id=tenant_id,
            )
        )
    if not cfg.contexts:
        cfg.contexts.append(
            Context(
                name="default",
                cluster=cfg.clusters[0].name,
                auth=cfg.auth_entries[0].name,
            )
        )
    return cfg


def _apply_env_overrides(cfg: CVEsConfig) -> CVEsConfig:
    """Apply CVES_* environment variable overrides."""
    ctx_name = os.environ.get("CVES_CONTEXT")
    if ctx_name:
        cfg.current_context = ctx_name

    # Endpoint overrides for the active cluster
    cluster = cfg.get_active_cluster()
    if cluster:
        env_map = {
            "CVES_SCAN_ORCHESTRATOR_URL": "scan_orchestrator",
            "CVES_DISCOVERY_URL": "discovery_engine",
            "CVES_GRAPH_URL": "asset_graph_engine",
            "CVES_CORRELATION_URL": "ai_correlation_layer",
            "CVES_REPORTING_URL": "reporting_engine",
            "CVES_RUNTIME_URL": "runtime_analysis_engine",
            "CVES_JS_URL": "js_intelligence_engine",
            "CVES_EXPOSURE_URL": "exposure_validation_engine",
        }
        for env_key, field_name in env_map.items():
            val = os.environ.get(env_key)
            if val:
                setattr(cluster.endpoints, field_name, val)

    return cfg


def load(profile: str = "default") -> CVEsConfig:
    """Load config from disk, apply env overrides, inject defaults."""
    if _CONFIG_FILE.exists():
        raw = yaml.safe_load(_CONFIG_FILE.read_text(encoding="utf-8")) or {}
        cfg = CVEsConfig.model_validate(raw)
    else:
        cfg = CVEsConfig()

    # Profile maps to current_context override
    if profile != "default":
        cfg.current_context = profile

    cfg = _ensure_default_config(cfg)
    cfg = _apply_env_overrides(cfg)
    return cfg


def save(cfg: CVEsConfig) -> None:
    """Persist config to disk."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = cfg.model_dump(exclude_none=True)
    _CONFIG_FILE.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")


def set_current_context(name: str) -> None:
    cfg = load()
    if cfg.get_context(name) is None:
        from rich.console import Console

        Console(stderr=True).print(f"[red]Context '{name}' does not exist.[/red]")
        raise SystemExit(1)
    cfg.current_context = name
    save(cfg)
