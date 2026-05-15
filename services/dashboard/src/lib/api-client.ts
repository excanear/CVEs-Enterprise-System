/**
 * Typed fetch wrapper — all calls go through Next.js /api/proxy/[service]/[...path]
 * so CORS and X-Tenant-ID injection happen server-side in the Route Handler.
 */

export type ApiError = { status: number; message: string };

function getTenantId(): string {
  if (typeof window !== "undefined") {
    return (
      sessionStorage.getItem("tenant_id") ??
      process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID ??
      "dev-tenant"
    );
  }
  return process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID ?? "dev-tenant";
}

async function apiFetch<T>(
  service: string,
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
  options?: RequestInit
): Promise<T> {
  const origin =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:3000";
  const url = new URL(`/api/proxy/${service}/${path}`, origin);

  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined) url.searchParams.set(k, String(v));
    });
  }

  const response = await fetch(url.toString(), {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Tenant-ID": getTenantId(),
      ...(options?.headers as Record<string, string>),
    },
  });

  if (!response.ok) {
    const msg = await response.text().catch(() => response.statusText);
    throw { status: response.status, message: msg } as ApiError;
  }

  return response.json() as Promise<T>;
}

// ── ACL ────────────────────────────────────────────────────────────────────
export const aclApi = {
  getRiskSummary: (tenantId: string) =>
    apiFetch("acl", "correlation/risk-summary", { tenant_id: tenantId }),

  getClusters: (tenantId: string) =>
    apiFetch("acl", "correlation/clusters", { tenant_id: tenantId }),

  getExposures: (tenantId: string) =>
    apiFetch("acl", "correlation/exposures/prioritized", { tenant_id: tenantId }),

  getRemediation: (clusterId: string, tenantId: string) =>
    apiFetch("acl", `correlation/remediation/${clusterId}`, { tenant_id: tenantId }),
};

// ── AGE ────────────────────────────────────────────────────────────────────
export const ageApi = {
  getAssets: (tenantId: string, limit = 100) =>
    apiFetch("age", "graph/assets", { tenant_id: tenantId, limit }),

  getAttackPaths: (tenantId: string, maxPaths = 30) =>
    apiFetch("age", "graph/attack-paths", { tenant_id: tenantId, max_paths: maxPaths }),

  getPropagation: (tenantId: string, maxDepth = 5) =>
    apiFetch("age", "graph/exposure-propagation", { tenant_id: tenantId, max_depth: maxDepth }),

  getStats: (tenantId: string) =>
    apiFetch("age", "graph/stats", { tenant_id: tenantId }),
};

// ── EVE ────────────────────────────────────────────────────────────────────
export const eveApi = {
  listJobs: (tenantId: string, limit = 50) =>
    apiFetch("eve", "exposure-validation/jobs", { tenant_id: tenantId, limit }),

  getEvidence: (jobId: string) =>
    apiFetch("eve", `exposure-validation/jobs/${jobId}/evidence`),

  getResult: (jobId: string) =>
    apiFetch("eve", `exposure-validation/jobs/${jobId}/result`),
};

// ── RAE ────────────────────────────────────────────────────────────────────
export const raeApi = {
  listSessions: (tenantId: string, limit = 20) =>
    apiFetch("rae", "runtime-analysis/sessions", { tenant_id: tenantId, limit }),

  getResult: (sessionId: string) =>
    apiFetch("rae", `runtime-analysis/sessions/${sessionId}/result`),

  getApis: (sessionId: string, limit = 200) =>
    apiFetch("rae", `runtime-analysis/sessions/${sessionId}/apis`, { limit }),
};

// ── JSI ────────────────────────────────────────────────────────────────────
export const jsiApi = {
  listJobs: (tenantId: string, limit = 50) =>
    apiFetch("jsi", "js-intelligence/jobs", { tenant_id: tenantId, limit }),

  getResult: (jobId: string) =>
    apiFetch("jsi", `js-intelligence/jobs/${jobId}/result`),
};

// ── RE ─────────────────────────────────────────────────────────────────────
export const reApi = {
  getExecutiveSummary: (tenantId: string) =>
    apiFetch("re", "reports/executive/summary", { tenant_id: tenantId }),

  getRemediationGuidance: (tenantId: string) =>
    apiFetch("re", "reports/remediation/guidance", { tenant_id: tenantId }),

  getComplianceMapping: (tenantId: string) =>
    apiFetch("re", "reports/compliance/mapping", { tenant_id: tenantId }),
};
