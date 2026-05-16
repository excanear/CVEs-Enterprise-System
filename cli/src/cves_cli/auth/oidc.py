"""OIDC Device Authorization Grant (RFC 8628) flow.

Usage:
    token = await device_flow_login(
        issuer="https://auth.example.com",
        client_id="cves-cli",
        audience="api.cves-platform",
    )
"""
from __future__ import annotations

import asyncio
import sys
import time
import webbrowser

import httpx


class OIDCError(Exception):
    pass


async def _get_device_code(
    client: httpx.AsyncClient,
    device_auth_url: str,
    client_id: str,
    scope: str,
    audience: str | None,
) -> dict:
    data: dict[str, str] = {"client_id": client_id, "scope": scope}
    if audience:
        data["audience"] = audience
    resp = await client.post(device_auth_url, data=data)
    resp.raise_for_status()
    return resp.json()


async def _exchange_device_code(
    client: httpx.AsyncClient,
    token_url: str,
    client_id: str,
    device_code: str,
    interval: int,
    expires_in: int,
) -> dict:
    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        resp = await client.post(
            token_url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            },
        )
        body = resp.json()
        err = body.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err:
            raise OIDCError(f"OIDC error: {err} — {body.get('error_description', '')}")
        return body
    raise OIDCError("Device authorization timed out.")


async def device_flow_login(
    *,
    issuer: str,
    client_id: str,
    scope: str = "openid profile offline_access",
    audience: str | None = None,
    open_browser: bool = True,
) -> dict:
    """Run OIDC device flow. Returns token response dict with access_token."""
    oidc_config_url = issuer.rstrip("/") + "/.well-known/openid-configuration"

    async with httpx.AsyncClient(timeout=30) as client:
        # Discover endpoints
        meta_resp = await client.get(oidc_config_url)
        meta_resp.raise_for_status()
        meta = meta_resp.json()

        device_auth_url: str = meta.get(
            "device_authorization_endpoint",
            issuer.rstrip("/") + "/oauth/device/code",
        )
        token_url: str = meta["token_endpoint"]

        # Get device code
        device_data = await _get_device_code(client, device_auth_url, client_id, scope, audience)

        user_code: str = device_data["user_code"]
        verification_uri: str = device_data.get("verification_uri_complete") or device_data["verification_uri"]
        interval: int = int(device_data.get("interval", 5))
        expires_in: int = int(device_data.get("expires_in", 300))

        # Prompt user
        print(f"\n  Open this URL to authenticate:\n\n    {verification_uri}\n", file=sys.stderr)
        print(f"  Code: [bold]{user_code}[/bold]" if False else f"  Code: {user_code}\n", file=sys.stderr)

        if open_browser:
            webbrowser.open(verification_uri)

        # Poll for token
        return await _exchange_device_code(
            client, token_url, client_id, device_data["device_code"], interval, expires_in
        )


async def refresh_token_grant(
    *,
    token_url: str,
    client_id: str,
    refresh_token: str,
) -> dict:
    """Exchange a refresh token for a new access token."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
        )
        resp.raise_for_status()
        return resp.json()
