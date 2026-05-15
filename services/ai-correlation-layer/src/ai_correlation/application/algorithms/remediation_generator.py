"""Remediation Generator — template lookup + optional LLM summarization.

Step 1 (always): Deterministic template lookup keyed by ExposureType.
Step 2 (optional): LLM contextualizes the template steps using validated finding data.

The LLM is NEVER used to identify or discover vulnerabilities.
It ONLY synthesizes pre-computed remediation steps into a narrative.
Graceful degradation: LLM unavailable → return template steps only.
"""
from __future__ import annotations

import structlog

from ai_correlation.domain.entities.evidence_cluster import EvidenceCluster
from ai_correlation.domain.value_objects.remediation_plan import RemediationPlan
from ai_correlation.infrastructure.ai.llm_client import AsyncLLMClient

log = structlog.get_logger(__name__)

# ── Remediation templates keyed by ExposureType value ─────────────────────────

TEMPLATES: dict[str, list[str]] = {
    "MISSING_AUTH": [
        "Implement authentication middleware on all exposed endpoints before any business logic.",
        "Add JWT or OAuth2 validation with strict issuer and audience verification.",
        "Enforce token expiry; reject tokens with iat older than session TTL.",
        "Configure rate limiting on authentication endpoints to prevent credential stuffing.",
        "Log all authentication failures with tenant_id and source IP for SIEM ingestion.",
    ],
    "EXPOSED_API": [
        "Restrict API access to authenticated and authorized callers only.",
        "Apply API gateway rate limiting and quota enforcement per tenant.",
        "Remove or gate internal/admin API routes from the public routing table.",
        "Audit all routes marked EXPOSED_ROUTE in the asset graph and apply allow-listing.",
        "Enable CORS restrictive policy — explicitly list trusted origins.",
    ],
    "CORS_MISCONFIGURATION": [
        "Replace wildcard Access-Control-Allow-Origin (*) with an explicit trusted-origin allowlist.",
        "Remove Access-Control-Allow-Credentials: true when using wildcard origins.",
        "Audit the TRUSTS graph edges flagged by the Asset Graph Engine for misconfigured cross-origin trust.",
        "Implement server-side origin validation against a maintained allowlist in environment config.",
        "Add Content-Security-Policy headers in addition to CORS headers for defense-in-depth.",
    ],
    "SECURITY_HEADER_MISSING": [
        "Add Content-Security-Policy header with a restrictive policy and report-uri directive.",
        "Enable Strict-Transport-Security (HSTS) with min max-age=31536000, includeSubDomains.",
        "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
        "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        "Add Permissions-Policy header to restrict browser feature access.",
    ],
    "PATH_TRAVERSAL": [
        "Validate and canonicalize all user-supplied file paths before use.",
        "Use os.path.realpath / Path.resolve() and verify the resolved path starts with the expected base directory.",
        "Reject any path containing sequences like ../, ..\\ or null bytes.",
        "Run file-serving endpoints under a dedicated low-privilege user account.",
        "Apply chroot or container-level filesystem restrictions on file-serving services.",
    ],
    "INJECTION_SURFACE": [
        "Use parameterized queries (prepared statements) — never concatenate user input into SQL.",
        "Apply allowlist input validation: reject requests not matching the expected schema.",
        "Encode all output before rendering to prevent secondary injection in logs or responses.",
        "Deploy a WAF rule set tuned to the specific injection surface type detected.",
        "Conduct a targeted code review of all endpoints identified in the evidence cluster.",
    ],
    "EXPOSED_ROUTE": [
        "Remove unauthenticated routes that expose internal functionality from the public router.",
        "Apply route-level authorization middleware; verify tenant scope on each request.",
        "Audit all routes in the asset graph with label ROUTE and no associated auth edge.",
        "Implement API versioning and deprecate legacy unauthenticated route versions.",
        "Use canary tokens on sensitive routes to detect unauthorized probing.",
    ],
    "WEBSOCKET_UNPROTECTED": [
        "Implement token-based authentication in the WebSocket handshake upgrade request.",
        "Validate the Origin header on WebSocket upgrade and reject unknown origins.",
        "Apply per-connection rate limiting and message size limits.",
        "Enforce tenant isolation at the WebSocket session layer.",
        "Log all WebSocket connection attempts with tenant_id and endpoint path.",
    ],
}

_DEFAULT_STEPS = [
    "Review the affected endpoint for security misconfigurations.",
    "Apply least-privilege access controls.",
    "Conduct a targeted security review with the development team.",
]


class RemediationGenerator:
    """Generates remediation plans from templates, optionally enriched by LLM."""

    def __init__(self, llm_client: AsyncLLMClient | None = None) -> None:
        self._llm = llm_client

    async def generate(self, cluster: EvidenceCluster) -> RemediationPlan:
        # Determine primary exposure type (most frequent in cluster)
        if cluster.items:
            type_counts: dict[str, int] = {}
            for item in cluster.items:
                type_counts[item.exposure_type] = type_counts.get(item.exposure_type, 0) + 1
            primary_type = max(type_counts, key=lambda t: type_counts[t])
        else:
            primary_type = "EXPOSED_API"

        steps = TEMPLATES.get(primary_type, _DEFAULT_STEPS)

        # LLM enrichment — only if enabled, uses validated data only
        llm_narrative: str | None = None
        llm_enriched = False

        if self._llm and self._llm.enabled and cluster.items:
            representative = max(cluster.items, key=lambda i: i.confidence)
            try:
                llm_narrative = await self._llm.summarize_remediation(
                    exposure_type=primary_type,
                    target_url=representative.target_url,
                    confidence=representative.confidence,
                    poc_triggered=representative.poc_triggered,
                    evidence_summary=representative.evidence_summary,
                    cluster_size=cluster.size,
                    propagation_depth=cluster.max_propagation_depth,
                    remediation_steps=steps,
                )
                llm_enriched = llm_narrative is not None
            except Exception as exc:
                log.warning("acl.remediation.llm_error", cluster_id=cluster.cluster_id, error=str(exc))

        log.info(
            "acl.remediation.generated",
            cluster_id=cluster.cluster_id,
            exposure_type=primary_type,
            llm_enriched=llm_enriched,
        )

        return RemediationPlan(
            cluster_id=cluster.cluster_id,
            exposure_type=primary_type,
            steps=list(steps),
            llm_enriched=llm_enriched,
            llm_narrative=llm_narrative,
            template_id=primary_type,
        )
