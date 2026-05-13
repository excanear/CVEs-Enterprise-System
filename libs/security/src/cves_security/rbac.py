"""Role-Based Access Control policy engine.

Permission model: tenant:role:resource:action

Built-in roles (extensible via custom_roles):
  ADMIN       — full access to all resources in their tenant.
  ANALYST     — read access to findings, no write on scope config.
  OPERATOR    — read/write on scans, no access to audit log.
  READ_ONLY   — GET endpoints only, no mutation.

The @require_permission decorator is a FastAPI dependency factory.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status

logger = logging.getLogger(__name__)


class Permission(StrEnum):
    # Assets
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    ASSET_SCOPE = "asset:scope"
    ASSET_DELETE = "asset:delete"

    # Scans
    SCAN_READ = "scan:read"
    SCAN_TRIGGER = "scan:trigger"
    SCAN_CANCEL = "scan:cancel"

    # Exposures / Findings
    EXPOSURE_READ = "exposure:read"
    EXPOSURE_VALIDATE = "exposure:validate"
    EXPOSURE_SUPPRESS = "exposure:suppress"

    # Alerts
    ALERT_READ = "alert:read"
    ALERT_ACKNOWLEDGE = "alert:acknowledge"

    # Admin
    TENANT_MANAGE = "tenant:manage"
    AUDIT_READ = "audit:read"
    USER_MANAGE = "user:manage"


_ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "ADMIN": set(Permission),
    "ANALYST": {
        Permission.ASSET_READ,
        Permission.SCAN_READ,
        Permission.EXPOSURE_READ,
        Permission.ALERT_READ,
        Permission.AUDIT_READ,
    },
    "OPERATOR": {
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.SCAN_READ,
        Permission.SCAN_TRIGGER,
        Permission.SCAN_CANCEL,
        Permission.EXPOSURE_READ,
        Permission.ALERT_READ,
        Permission.ALERT_ACKNOWLEDGE,
    },
    "READ_ONLY": {
        Permission.ASSET_READ,
        Permission.SCAN_READ,
        Permission.EXPOSURE_READ,
        Permission.ALERT_READ,
    },
}


class RBACPolicy:
    """Evaluates whether a set of roles grants a required permission."""

    def __init__(self, custom_roles: dict[str, set[Permission]] | None = None) -> None:
        self._permissions = dict(_ROLE_PERMISSIONS)
        if custom_roles:
            self._permissions.update(custom_roles)

    def has_permission(self, roles: list[str], permission: Permission) -> bool:
        """Return True if any of the provided roles grants permission."""
        for role in roles:
            if permission in self._permissions.get(role.upper(), set()):
                return True
        return False

    def require_permission(self, permission: Permission) -> Callable:
        """FastAPI dependency factory — raises 403 if permission is absent.

        Usage::

            @router.get("/assets")
            async def list_assets(
                _: None = Depends(rbac.require_permission(Permission.ASSET_READ)),
                ...
            ): ...
        """

        async def _check(request: Request) -> None:
            claims: dict[str, Any] = getattr(request.state, "jwt_claims", {})
            roles: list[str] = claims.get("roles", [])
            if not self.has_permission(roles, permission):
                logger.warning(
                    "rbac_permission_denied",
                    extra={
                        "required": str(permission),
                        "roles": roles,
                        "path": request.url.path,
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required.",
                )

        return Depends(_check)
