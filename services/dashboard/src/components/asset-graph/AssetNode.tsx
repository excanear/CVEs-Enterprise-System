"use client";

import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";
import { TIER_HEX } from "@/lib/tier-colors";
import type { AssetNodeData } from "@/lib/graph-transforms";

const ASSET_TYPE_COLOR: Record<string, string> = {
  endpoint: "#3b82f6",
  api: "#8b5cf6",
  web: "#06b6d4",
  database: "#f59e0b",
  service: "#10b981",
  asset: "#64748b",
};

export const AssetNode = memo(function AssetNode({ data, selected }: NodeProps<AssetNodeData>) {
  const typeColor = ASSET_TYPE_COLOR[data.asset_type ?? "asset"] ?? "#64748b";
  const riskColor = data.risk_score != null ? TIER_HEX[riskToTier(data.risk_score)] : undefined;
  const borderColor = riskColor ?? typeColor;

  return (
    <div
      className={cn(
        "relative flex min-w-[160px] max-w-[220px] flex-col rounded-lg border-2 bg-card px-3 py-2 shadow-md transition-shadow",
        selected && "shadow-lg shadow-primary/20"
      )}
      style={{ borderColor }}
    >
      <Handle type="target" position={Position.Left} className="!bg-border" />

      {/* Type label */}
      <span
        className="text-[9px] font-bold uppercase tracking-widest"
        style={{ color: typeColor }}
      >
        {data.asset_type ?? "asset"}
      </span>

      {/* Primary label */}
      <p className="mt-0.5 truncate text-xs font-semibold text-foreground" title={data.label}>
        {data.label}
      </p>

      {/* URL / host line */}
      {data.host && data.host !== data.label && (
        <p className="mt-0.5 truncate text-[10px] text-muted-foreground" title={data.host}>
          {data.host}
        </p>
      )}

      {/* Risk score pill */}
      {data.risk_score != null && (
        <span
          className="mt-1.5 self-start rounded-full px-1.5 py-0.5 text-[9px] font-bold text-white"
          style={{ backgroundColor: TIER_HEX[riskToTier(data.risk_score)] }}
        >
          {(data.risk_score * 100).toFixed(0)}%
        </span>
      )}

      <Handle type="source" position={Position.Right} className="!bg-border" />
    </div>
  );
});

function riskToTier(score: number): string {
  if (score >= 0.9) return "CRITICAL";
  if (score >= 0.7) return "HIGH";
  if (score >= 0.4) return "MEDIUM";
  return "LOW";
}
