// ── ACL ────────────────────────────────────────────────────────────────────
export interface RiskSummary {
  tenant_id: string;
  total_clusters: number;
  total_exposures: number;
  tier_breakdown: Record<string, number>;
  avg_confidence: number;
  top_exposures: ExposurePrioritized[];
  generated_at: string;
}

export interface Cluster {
  cluster_id: string;
  tenant_id: string;
  session_id: string;
  size: number;
  tier: Tier;
  host?: string;
  avg_confidence: number;
  poc_triggered_count: number;
  exposure_types: string[];
  created_at: string;
}

export interface ExposurePrioritized {
  exposure_id: string;
  tenant_id: string;
  target_url: string;
  exposure_type: string;
  tier: Tier;
  composite_score: number;
  rationale: string;
}

export interface RemediationPlan {
  cluster_id: string;
  exposure_type: string;
  tier: Tier;
  steps: string[];
  llm_enriched: boolean;
  llm_narrative?: string;
}

// ── AGE ────────────────────────────────────────────────────────────────────
export interface AGEAsset {
  node_id: string;
  url?: string;
  host?: string;
  port?: number;
  scheme?: string;
  asset_type?: string;
}

export interface PathNode {
  node_id: string;
  label: string;
  url?: string;
  host?: string;
}

export interface AttackPath {
  source_endpoint_id: string;
  target_asset_id: string;
  hops: number;
  risk_score: number;
  nodes: PathNode[];
}

export interface PropagationHop {
  asset_id: string;
  url?: string;
  host?: string;
  hop_distance: number;
  reached_via: string;
}

export interface PropagationResult {
  origin_endpoint_id: string;
  affected_count: number;
  propagation_depth: number;
  max_hops_reached: boolean;
  affected_assets: PropagationHop[];
}

// ── EVE ────────────────────────────────────────────────────────────────────
export type Tier = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type JobStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
export type Verdict = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "INCONCLUSIVE";

export interface ValidationJob {
  job_id: string;
  tenant_id: string;
  target_url: string;
  exposure_type: string;
  status: JobStatus;
  result_id?: string;
  failure_reason?: string;
  duration_seconds?: number;
  created_at: string;
}

export interface EvidenceBreakdown {
  reachability: {
    is_reachable: boolean;
    http_status?: number;
    response_time_ms?: number;
    required_playwright?: boolean;
    error?: string;
  };
  middleware: {
    score: number;
    csp_present: boolean;
    hsts_present: boolean;
    x_frame_options?: string;
    cors_wildcard: boolean;
    cors_credentials_wildcard: boolean;
    missing_headers: string[];
  };
  parser: {
    content_type?: string;
    has_reflected_input: boolean;
    reflected_in?: string;
    has_json_error_leak: boolean;
    has_stack_trace: boolean;
    has_debug_info: boolean;
    risk_indicators: string[];
    risk_score: number;
  };
  poc: {
    probe_type: string;
    triggered: boolean;
    evidence?: string;
    safe: boolean;
  };
  inference_score_estimate: number;
  correlation_count: number;
}

// ── RAE ────────────────────────────────────────────────────────────────────
export interface AnalysisSession {
  session_id: string;
  tenant_id: string;
  target_url: string;
  status: JobStatus;
  result_id?: string;
  failure_reason?: string;
  duration_seconds?: number;
  created_at: string;
}

export interface InterceptedAPI {
  url: string;
  method: string;
  is_graphql: boolean;
  status_code?: number;
  params: string[];
}

export interface AnalysisResult {
  result_id: string;
  session_id: string;
  intercepted_apis_count: number;
  websocket_endpoints_count: number;
  spa_routes_count: number;
  frameworks: Array<{ name: string; version?: string; confidence?: number }>;
  dom_snapshot?: Record<string, unknown>;
  hydration_markers: Record<string, unknown>;
}

// ── JSI ────────────────────────────────────────────────────────────────────
export interface JSJob {
  job_id: string;
  tenant_id: string;
  target_url: string;
  status: string;
  result_id?: string;
  failure_reason?: string;
  duration_seconds?: number;
  stats: Record<string, number>;
  created_at: string;
}

// ── RE ─────────────────────────────────────────────────────────────────────
export interface ExecutiveSummary {
  tenant_id: string;
  total_findings: number;
  total_clusters: number;
  tier_breakdown: Record<string, number>;
  top_findings: ExposurePrioritized[];
  generated_at: string;
}

export interface RemediationGuidance {
  cluster_id: string;
  exposure_type: string;
  tier: Tier;
  steps: string[];
  llm_enriched: boolean;
  llm_narrative?: string;
}

export interface ComplianceFinding {
  exposure_id: string;
  target_url: string;
  exposure_type: string;
  tier: Tier;
  composite_score: number;
  owasp_top10: string[];
  cwe_ids: string[];
  pci_dss_40: string[];
  iso_27001_2022: string[];
  nist_csf_20: string[];
}

export interface Report {
  report_id: string;
  tenant_id: string;
  report_type: string;
  report_format: string;
  status: string;
  finding_count: number;
  error?: string;
  created_at: string;
  generated_at?: string;
}

// ── Scan Orchestrator ──────────────────────────────────────────────────────
export interface Scan {
  scan_id: string;
  tenant_id: string;
  scan_type: string;
  status: string;
  priority: string;
  tasks_total: number;
  tasks_completed: number;
  tasks_failed: number;
  tasks_retrying: number;
  progress_pct: number;
  initiated_by: string;
}
