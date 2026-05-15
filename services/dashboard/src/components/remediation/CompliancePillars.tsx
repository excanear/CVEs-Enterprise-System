"use client";

import type { ComplianceFinding } from "@/types/api";

interface Props {
  findings: ComplianceFinding[];
}

const PILLARS = [
  { key: "owasp_top10", label: "OWASP Top 10", color: "#3b82f6" },
  { key: "cwe_ids", label: "CWE IDs", color: "#8b5cf6" },
  { key: "pci_dss_40", label: "PCI DSS 4.0", color: "#f59e0b" },
  { key: "iso_27001_2022", label: "ISO 27001", color: "#10b981" },
  { key: "nist_csf_20", label: "NIST CSF 2.0", color: "#ef4444" },
] as const;

export function CompliancePillars({ findings }: Props) {
  // Aggregate unique codes per pillar
  const pillarData = PILLARS.map(({ key, label, color }) => {
    const codes = Array.from(
      new Set(findings.flatMap((f) => f[key] as string[]))
    ).slice(0, 8);
    return { key, label, color, codes };
  });

  return (
    <div className="space-y-4">
      {pillarData.map(({ key, label, color, codes }) => (
        <div key={key}>
          <div className="flex items-center gap-2 mb-2">
            <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-xs font-semibold text-foreground">{label}</span>
            <span className="text-xs text-muted-foreground ml-auto">
              {codes.length} controls
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {codes.length === 0 && (
              <span className="text-xs text-muted-foreground">None mapped</span>
            )}
            {codes.map((code) => (
              <span
                key={code}
                className="rounded-sm px-1.5 py-0.5 text-[10px] font-mono font-medium text-white"
                style={{ backgroundColor: color + "40", color }}
              >
                {code}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
