"use client";

import { CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import type { EvidenceBreakdown } from "@/types/api";

interface Props {
  evidence: EvidenceBreakdown | null;
}

interface Stage {
  key: keyof EvidenceBreakdown;
  label: string;
  description: string;
  passed: (e: EvidenceBreakdown) => boolean;
}

const STAGES: Stage[] = [
  {
    key: "reachability",
    label: "Reachability",
    description: "HTTP connectivity and response time",
    passed: (e) => e.reachability.is_reachable,
  },
  {
    key: "middleware",
    label: "Middleware",
    description: "Security headers & CORS policy",
    passed: (e) => e.middleware.score >= 0.5,
  },
  {
    key: "parser",
    label: "Response Parser",
    description: "Input reflection, error leaks, debug info",
    passed: (e) => e.parser.risk_score >= 0.4,
  },
  {
    key: "poc",
    label: "PoC Execution",
    description: "Active probe execution result",
    passed: (e) => e.poc.triggered,
  },
];

export function EvidenceTimeline({ evidence }: Props) {
  if (!evidence) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
        Select a job to view evidence
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Overall confidence bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-xs">
          <span className="text-muted-foreground">Inference Score</span>
          <span className="font-mono font-semibold">
            {(evidence.inference_score_estimate * 100).toFixed(1)}%
          </span>
        </div>
        <Progress value={evidence.inference_score_estimate * 100} />
      </div>

      {/* Stage timeline */}
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-4 top-5 bottom-5 w-px bg-border" />

        <div className="space-y-3">
          {STAGES.map((stage, idx) => {
            const passed = stage.passed(evidence);
            const Icon = passed ? CheckCircle2 : XCircle;
            const iconColor = passed ? "text-green-400" : "text-red-400";

            return (
              <div key={stage.key} className="relative flex gap-4">
                {/* Icon */}
                <div className="relative z-10 flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-background">
                  <Icon className={`h-5 w-5 ${iconColor}`} />
                </div>

                {/* Content */}
                <div className="flex-1 rounded-lg border border-border bg-card p-3">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-semibold">{stage.label}</p>
                    <span className={`text-xs font-medium ${iconColor}`}>
                      {passed ? "PASS" : "FAIL"}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">{stage.description}</p>

                  {/* Stage-specific detail */}
                  <StageDetail stage={stage.key} evidence={evidence} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function StageDetail({
  stage,
  evidence,
}: {
  stage: keyof EvidenceBreakdown;
  evidence: EvidenceBreakdown;
}) {
  if (stage === "reachability") {
    const r = evidence.reachability;
    return (
      <div className="mt-2 flex gap-4 text-xs text-muted-foreground">
        <span>HTTP {r.http_status ?? "—"}</span>
        {r.response_time_ms != null && <span>{r.response_time_ms.toFixed(0)}ms</span>}
        {r.error && <span className="text-red-400">{r.error}</span>}
      </div>
    );
  }

  if (stage === "middleware") {
    const m = evidence.middleware;
    return (
      <div className="mt-2 space-y-1 text-xs">
        <div className="flex gap-3 text-muted-foreground">
          <span>Score: {(m.score * 100).toFixed(0)}%</span>
          {m.cors_wildcard && <span className="text-red-400">CORS wildcard</span>}
          {!m.csp_present && <span className="text-yellow-400">No CSP</span>}
          {!m.hsts_present && <span className="text-yellow-400">No HSTS</span>}
        </div>
        {m.missing_headers.length > 0 && (
          <p className="text-muted-foreground">
            Missing: {m.missing_headers.join(", ")}
          </p>
        )}
      </div>
    );
  }

  if (stage === "parser") {
    const p = evidence.parser;
    return (
      <div className="mt-2 flex flex-wrap gap-2 text-xs">
        {p.has_reflected_input && <span className="text-red-400">Reflected input</span>}
        {p.has_stack_trace && <span className="text-red-400">Stack trace</span>}
        {p.has_json_error_leak && <span className="text-orange-400">JSON error leak</span>}
        {p.has_debug_info && <span className="text-yellow-400">Debug info</span>}
        <span className="text-muted-foreground">Risk: {(p.risk_score * 100).toFixed(0)}%</span>
      </div>
    );
  }

  if (stage === "poc") {
    const p = evidence.poc;
    return (
      <div className="mt-2 text-xs space-y-1">
        <div className="flex gap-3 text-muted-foreground">
          <span>Probe: {p.probe_type}</span>
          {p.triggered && <span className="text-red-400 font-medium">TRIGGERED</span>}
          {!p.safe && <span className="text-orange-400">Not safe to re-run</span>}
        </div>
        {p.evidence && (
          <p className="font-mono bg-muted rounded p-1.5 text-foreground whitespace-pre-wrap max-h-20 overflow-auto">
            {p.evidence.slice(0, 300)}
          </p>
        )}
      </div>
    );
  }

  return null;
}
