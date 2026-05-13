"""Application commands for Asset Graph Engine."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class IngestEnvelopeCommand(BaseModel):
    """Manually ingest a raw event envelope into the graph."""

    model_config = ConfigDict(frozen=True)

    event_type: str
    tenant_id: str
    payload: dict = Field(default_factory=dict)
    correlation_id: str = ""


class QueryAttackPathsCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    max_paths: int = Field(default=20, ge=1, le=100)


class QueryTrustChainsCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    asset_id: str
    max_depth: int = Field(default=10, ge=1, le=15)


class QueryPropagationCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    max_depth: int = Field(default=5, ge=1, le=10)


class QueryDependenciesCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str


class QueryInfraMapCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str


class QueryStatsCommand(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: str
