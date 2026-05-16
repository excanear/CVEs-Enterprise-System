"""Base async HTTP client — auth injection, retry, error handling."""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import httpx


class CVEsError(Exception):
    """Base CLI error."""


class AuthError(CVEsError):
    """Authentication / authorization failure."""


class NotFoundError(CVEsError):
    """Resource not found (404)."""


class ServiceError(CVEsError):
    """Unexpected service error (4xx/5xx)."""


class RequestTimeoutError(CVEsError):
    """Request timed out."""


def _resolve_auth_headers(auth_name: str, auth_type: str, tenant_id: str | None) -> dict[str, str]:
    """Build Authorization + X-Tenant-ID headers from stored credentials."""
    headers: dict[str, str] = {}

    if auth_type == "api_key":
        from cves_cli.auth.api_key import get_api_key

        key = get_api_key(auth_name) or os.environ.get("CVES_API_KEY")
        if key:
            headers["X-API-Key"] = key
    else:
        from cves_cli.auth.token_cache import get_cached_token, get_refresh_token

        token = get_cached_token(auth_name)
        if not token:
            # Attempt silent refresh
            token = _try_refresh(auth_name)
        if token:
            headers["Authorization"] = f"Bearer {token}"

    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id

    return headers


def _try_refresh(auth_name: str) -> str | None:
    """Attempt to refresh OIDC token synchronously (called from sync context)."""
    from cves_cli.auth.token_cache import get_refresh_token, store_token
    from cves_cli.config.loader import load

    refresh = get_refresh_token(auth_name)
    if not refresh:
        return None
    cfg = load()
    ae = cfg.get_auth_entry(auth_name)
    if ae is None or not ae.token_url or not ae.client_id:
        return None

    try:
        import anyio
        from cves_cli.auth.oidc import refresh_token_grant

        tokens = anyio.from_thread.run_sync(
            lambda: anyio.run(
                refresh_token_grant,
                token_url=ae.token_url,
                client_id=ae.client_id,
                refresh_token=refresh,
            )
        )
        access_token = tokens["access_token"]
        store_token(auth_name, access_token, tokens.get("refresh_token", refresh))
        return access_token
    except Exception:
        return None


class CVEsHTTPClient:
    """Thin async HTTP client with auth injection, retry, and error mapping."""

    def __init__(
        self,
        base_url: str,
        auth_name: str = "default",
        auth_type: str = "api_key",
        tenant_id: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_name = auth_name
        self._auth_type = auth_type
        self._tenant_id = tenant_id
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "CVEsHTTPClient":
        headers = _resolve_auth_headers(self._auth_name, self._auth_type, self._tenant_id)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={**headers, "Accept": "application/json", "User-Agent": "cves-cli/0.1"},
            http2=True,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _handle_response(self, resp: httpx.Response) -> dict | list | bytes:
        if resp.status_code == 401:
            raise AuthError("Authentication failed. Run: cves auth login")
        if resp.status_code == 403:
            raise AuthError(f"Permission denied: {resp.url.path}")
        if resp.status_code == 404:
            raise NotFoundError(f"Not found: {resp.url.path}")
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text[:200])
            except Exception:
                detail = resp.text[:200]
            raise ServiceError(f"HTTP {resp.status_code}: {detail}")
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.content

    async def _request(
        self,
        method: str,
        path: str,
        *,
        retries: int = 2,
        **kwargs: Any,
    ) -> dict | list | bytes:
        assert self._client is not None, "Use as async context manager"
        for attempt in range(retries + 1):
            try:
                resp = await self._client.request(method, path, **kwargs)
                if resp.status_code in (429, 503) and attempt < retries:
                    retry_after = int(resp.headers.get("Retry-After", 2 ** attempt * 2))
                    await asyncio.sleep(retry_after)
                    continue
                return self._handle_response(resp)  # type: ignore[return-value]
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(2**attempt)
                    continue
                raise RequestTimeoutError(f"Request timed out: {method} {path}") from exc
            except httpx.ConnectError as exc:
                raise ServiceError(f"Cannot connect to {self._base_url}: {exc}") from exc
        raise ServiceError("Max retries exceeded")  # pragma: no cover

    async def get(self, path: str, **kwargs: Any) -> dict | list | bytes:
        return await self._request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> dict | list | bytes:
        return await self._request("POST", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> dict | list | bytes:
        return await self._request("DELETE", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> dict | list | bytes:
        return await self._request("PATCH", path, **kwargs)

    async def get_stream(self, path: str, **kwargs: Any) -> bytes:
        """Download binary content (PDF, CSV) without JSON parsing."""
        assert self._client is not None
        resp = await self._client.get(path, **kwargs)
        if resp.status_code >= 400:
            self._handle_response(resp)
        return resp.content


def build_client(
    base_url: str,
    *,
    auth_name: str = "default",
    auth_type: str = "api_key",
    tenant_id: str | None = None,
    timeout: float = 30.0,
) -> CVEsHTTPClient:
    return CVEsHTTPClient(
        base_url=base_url,
        auth_name=auth_name,
        auth_type=auth_type,
        tenant_id=tenant_id,
        timeout=timeout,
    )
