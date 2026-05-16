"""Configuration models — Pydantic v2."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ServiceEndpoints(BaseModel):
    """Per-cluster service URL map."""

    scan_orchestrator: str = "http://localhost:8000"
    discovery_engine: str = "http://localhost:8005"
    asset_graph_engine: str = "http://localhost:8001"
    ai_correlation_layer: str = "http://localhost:8008"
    reporting_engine: str = "http://localhost:8009"
    runtime_analysis_engine: str = "http://localhost:8006"
    js_intelligence_engine: str = "http://localhost:8007"
    exposure_validation_engine: str = "http://localhost:8009"


class Cluster(BaseModel):
    """Named cluster — a set of service base URLs."""

    name: str
    endpoints: ServiceEndpoints = Field(default_factory=ServiceEndpoints)


class AuthEntry(BaseModel):
    """Named auth entry. Secrets are in OS keyring, NOT here."""

    name: str
    type: str = "api_key"        # api_key | oidc | token
    tenant_id: str | None = None

    # OIDC fields
    issuer: str | None = None
    client_id: str | None = None
    token_url: str | None = None
    audience: str | None = None


class Context(BaseModel):
    """Named context — a (cluster, auth, tenant_id) tuple."""

    name: str
    cluster: str
    auth: str
    tenant_id: str | None = None
    default_output: str = "table"


class CVEsConfig(BaseModel):
    """Root config — maps to ~/.config/cves/config.yaml."""

    current_context: str = "default"
    contexts: list[Context] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    auth_entries: list[AuthEntry] = Field(default_factory=list)

    # ── Lookups ───────────────────────────────────────────────────────────

    def get_context(self, name: str) -> Context | None:
        return next((c for c in self.contexts if c.name == name), None)

    def get_cluster(self, name: str) -> Cluster | None:
        return next((c for c in self.clusters if c.name == name), None)

    def get_auth_entry(self, name: str) -> AuthEntry | None:
        return next((a for a in self.auth_entries if a.name == name), None)

    def get_active_context(self) -> Context | None:
        return self.get_context(self.current_context)

    def get_active_cluster(self) -> Cluster | None:
        ctx = self.get_active_context()
        if ctx is None:
            return None
        return self.get_cluster(ctx.cluster)

    def get_active_auth_entry(self) -> AuthEntry | None:
        ctx = self.get_active_context()
        if ctx is None:
            return None
        return self.get_auth_entry(ctx.auth)

    def get_active_endpoints(self) -> ServiceEndpoints:
        cluster = self.get_active_cluster()
        if cluster:
            return cluster.endpoints
        return ServiceEndpoints()

    # ── Mutations ─────────────────────────────────────────────────────────

    def upsert_auth_entry(self, entry: AuthEntry) -> None:
        self.auth_entries = [a for a in self.auth_entries if a.name != entry.name]
        self.auth_entries.append(entry)

    def upsert_cluster(self, cluster: Cluster) -> None:
        self.clusters = [c for c in self.clusters if c.name != cluster.name]
        self.clusters.append(cluster)

    def upsert_context(self, ctx: Context) -> None:
        self.contexts = [c for c in self.contexts if c.name != ctx.name]
        self.contexts.append(ctx)

    def remove_auth_entry(self, name: str) -> None:
        self.auth_entries = [a for a in self.auth_entries if a.name != name]

    def remove_context(self, name: str) -> None:
        self.contexts = [c for c in self.contexts if c.name != name]
