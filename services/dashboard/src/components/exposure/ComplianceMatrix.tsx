"use client";

import { TIER_HEX } from "@/lib/tier-colors";
import { Skeleton } from "@/components/ui/skeleton";
import type { ComplianceFinding } from "@/types/api";

interface Props {
  findings: ComplianceFinding[];
  isLoading: boolean;
}

const FRAMEWORKS = [
  { key: "owasp_top10", label: "OWASP" },
  { key: "cwe_ids", label: "CWE" },
  { key: "pci_dss_40", label: "PCI DSS" },
  { key: "iso_27001_2022", label: "ISO 27001" },
  { key: "nist_csf_20", label: "NIST CSF" },
] as const;

export function ComplianceMatrix({ findings, isLoading }: Props) {
  if (isLoading) {
    return <Skeleton className="h-64 w-full" />;
  }

  if (findings.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-muted-foreground">
        No compliance data
      </div>
    );
  }

  // Build exposure_type × framework heatmap
  const typeSet = Array.from(new Set(findings.map((f) => f.exposure_type))).slice(0, 10);

  const heatmap: Record<string, Record<string, number>> = {};
  typeSet.forEach((t) => (heatmap[t] = {}));

  findings.forEach((f) => {
    if (!heatmap[f.exposure_type]) return;
    FRAMEWORKS.forEach(({ key, label }) => {
      const arr = f[key] as string[];
      heatmap[f.exposure_type][label] = (heatmap[f.exposure_type][label] ?? 0) + arr.length;
    });
  });

  return (
    <div className="overflow-auto">
      <table className="w-full text-xs">
        <thead>
          <tr>
            <th className="py-2 pr-4 text-left text-muted-foreground font-medium w-36">
              Exposure Type
            </th>
            {FRAMEWORKS.map(({ label }) => (
              <th key={label} className="px-3 py-2 text-center text-muted-foreground font-medium">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {typeSet.map((type) => {
            const row = heatmap[type];
            return (
              <tr key={type} className="border-t border-border">
                <td className="py-2 pr-4 font-medium text-foreground capitalize">
                  {type.replace(/_/g, " ")}
                </td>
                {FRAMEWORKS.map(({ label }) => {
                  const count = row[label] ?? 0;
                  const intensity = Math.min(count / 3, 1);
                  return (
                    <td key={label} className="px-3 py-2 text-center">
                      {count > 0 ? (
                        <span
                          className="inline-flex h-6 w-6 items-center justify-center rounded text-[10px] font-bold text-white"
                          style={{
                            backgroundColor: `rgba(239, 68, 68, ${0.2 + intensity * 0.8})`,
                          }}
                        >
                          {count}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
