"""EvaluationContext — structured data container for rule evaluation."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvaluationContext:
    """All data visible to rule conditions during a single evaluation pass.

    Typical usage::

        ctx = EvaluationContext.from_finding(
            finding={"category": "SQL_INJECTION", "severity": "CRITICAL"},
            asset={"hostname": "api.prod.example.com", "internet_facing": True},
            tenant_id="tenant-uuid",
        )
        engine.evaluate_detection(ctx)
    """

    # Primary flat data bag — always searched first by field-path resolver
    data: dict[str, Any] = field(default_factory=dict)

    # Named overlay namespaces — accessible via "asset.xxx", "finding.xxx", etc.
    asset: dict[str, Any] | None = None
    finding: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None
    event: dict[str, Any] | None = None

    tenant_id: str | None = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Flattening ────────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Produce a flat dict used as the condition evaluation namespace.

        Named namespaces (asset, finding, scan, event) are nested under their
        respective keys so dot-paths like "finding.category" resolve correctly.
        """
        ctx: dict[str, Any] = dict(self.data)
        if self.asset is not None:
            ctx["asset"] = self.asset
        if self.finding is not None:
            ctx["finding"] = self.finding
        if self.scan is not None:
            ctx["scan"] = self.scan
        if self.event is not None:
            ctx["event"] = self.event
        if self.tenant_id is not None:
            ctx["tenant_id"] = self.tenant_id
        ctx["_evaluated_at"] = self.evaluated_at.isoformat()
        return ctx

    # ── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_finding(
        cls,
        finding: dict[str, Any],
        *,
        asset: dict[str, Any] | None = None,
        scan: dict[str, Any] | None = None,
        tenant_id: str | None = None,
        **extra: Any,
    ) -> "EvaluationContext":
        return cls(
            data=extra,
            finding=finding,
            asset=asset,
            scan=scan,
            tenant_id=tenant_id,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvaluationContext":
        """Hydrate from a flat dict — namespaced keys are extracted automatically."""
        return cls(
            data={k: v for k, v in data.items() if k not in {"asset", "finding", "scan", "event", "tenant_id"}},
            asset=data.get("asset"),
            finding=data.get("finding"),
            scan=data.get("scan"),
            event=data.get("event"),
            tenant_id=data.get("tenant_id"),
        )

    @classmethod
    def for_validation(cls, payload: dict[str, Any], tenant_id: str | None = None) -> "EvaluationContext":
        """Create a context for input validation (no asset/finding overlay)."""
        return cls(data=payload, tenant_id=tenant_id)
