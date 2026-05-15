"""Typed commands for the correlation service."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TriggerCorrelationCommand:
    tenant_id: str
    session_id: str


@dataclass(frozen=True)
class GetSessionCommand:
    session_id: str


@dataclass(frozen=True)
class ListClustersCommand:
    tenant_id: str
    session_id: str | None = None


@dataclass(frozen=True)
class GetRankedPathsCommand:
    tenant_id: str
    limit: int = 50


@dataclass(frozen=True)
class GetPrioritizedExposuresCommand:
    tenant_id: str
    tier: str | None = None     # filter by RiskTier value, None = all
    limit: int = 100


@dataclass(frozen=True)
class GetRemediationCommand:
    cluster_id: str
    tenant_id: str


@dataclass(frozen=True)
class GetRiskSummaryCommand:
    tenant_id: str
    session_id: str | None = None
