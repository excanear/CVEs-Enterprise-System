"""Auth commands — login, logout, status, token, API keys."""
from __future__ import annotations

import sys
from typing import Optional

import anyio
import typer
from rich.console import Console

from cves_cli.output.formatter import fmt

auth_app = typer.Typer(name="auth", help="Authentication — login, logout, key management.", no_args_is_help=True)
keys_app = typer.Typer(name="keys", help="API key management.", no_args_is_help=True)
auth_app.add_typer(keys_app)


@auth_app.command("login")
def login(
    auth_type: str = typer.Option("api_key", "--type", "-t", help="api_key | oidc"),
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", envvar="CVES_API_KEY", help="API key value."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Print device URL instead of opening browser."),
) -> None:
    """Store credentials for the current profile."""
    from cves_cli.auth.api_key import store_api_key
    from cves_cli.auth.oidc import device_flow_login
    from cves_cli.auth.token_cache import store_token
    from cves_cli.config.loader import load

    cfg = load(profile)
    ae = cfg.get_auth_entry(profile)

    if auth_type == "api_key":
        key = api_key or typer.prompt("API Key", hide_input=True)
        store_api_key(profile, key)
        fmt.success(f"API key stored for profile '{profile}'.")
    elif auth_type == "oidc":
        if ae is None or not ae.issuer or not ae.client_id:
            fmt.error(
                f"Auth entry '{profile}' missing issuer/client_id. "
                "Run: cves context set auth.issuer <url>"
            )
            raise typer.Exit(1)

        async def _flow() -> None:
            tokens = await device_flow_login(
                issuer=ae.issuer,
                client_id=ae.client_id,
                audience=ae.audience,
                open_browser=not no_browser,
            )
            store_token(profile, tokens["access_token"], tokens.get("refresh_token"))
            fmt.success(f"Logged in via OIDC (profile: {profile}).")

        anyio.run(_flow)
    else:
        fmt.error(f"Unknown auth type: {auth_type}. Use 'api_key' or 'oidc'.")
        raise typer.Exit(1)


@auth_app.command("logout")
def logout(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
) -> None:
    """Clear stored credentials for the profile."""
    from cves_cli.auth.api_key import delete_api_key
    from cves_cli.auth.token_cache import clear_tokens

    delete_api_key(profile)
    clear_tokens(profile)
    fmt.success(f"Credentials cleared for profile '{profile}'.")


@auth_app.command("status")
def status(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
) -> None:
    """Show current auth status and token claims."""
    from cves_cli.auth.api_key import get_api_key
    from cves_cli.auth.token_cache import get_cached_token, get_token_claims

    token = get_cached_token(profile)
    key = get_api_key(profile)

    info: dict = {"profile": profile}
    if token:
        claims = get_token_claims(profile) or {}
        info["auth_type"] = "oidc"
        info["sub"] = claims.get("sub", "—")
        info["tenant_id"] = claims.get("tenant_id", "—")
        info["exp"] = claims.get("exp", "—")
        info["roles"] = claims.get("roles", claims.get("realm_access", {}).get("roles", []))
    elif key:
        info["auth_type"] = "api_key"
        info["key_prefix"] = key[:12] + "…"
    else:
        info["auth_type"] = "none"
        info["message"] = "Not authenticated. Run: cves auth login"

    fmt.print(info, title="Auth Status")


@auth_app.command("token")
def token(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
) -> None:
    """Print the raw access token (for piping to curl)."""
    from cves_cli.auth.token_cache import get_cached_token

    t = get_cached_token(profile)
    if not t:
        fmt.error("No active token. Run: cves auth login --type oidc")
        raise typer.Exit(1)
    print(t)


# ── API key sub-commands ──────────────────────────────────────────────────────

@keys_app.command("list")
def keys_list(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
) -> None:
    """List API keys registered in this profile."""
    from cves_cli.auth.api_key import get_api_key

    key = get_api_key(profile)
    if key:
        fmt.print([{"profile": profile, "key_prefix": key[:12] + "…"}], title="API Keys")
    else:
        fmt.warn("No API key stored for this profile.")


@keys_app.command("set")
def keys_set(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k"),
) -> None:
    """Store or update an API key."""
    from cves_cli.auth.api_key import store_api_key

    key = api_key or typer.prompt("API Key", hide_input=True)
    store_api_key(profile, key)
    fmt.success("API key updated.")


@keys_app.command("revoke")
def keys_revoke(
    profile: str = typer.Option("default", "--profile", "-p", envvar="CVES_PROFILE"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Remove the stored API key."""
    from cves_cli.auth.api_key import delete_api_key

    if not confirm:
        typer.confirm(f"Remove API key for profile '{profile}'?", abort=True)
    delete_api_key(profile)
    fmt.success("API key removed.")
