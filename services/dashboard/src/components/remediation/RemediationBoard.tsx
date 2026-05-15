"use client";

import { useState } from "react";
import { RemediationItem } from "./RemediationItem";
import { Skeleton } from "@/components/ui/skeleton";
import { TIER_HEX } from "@/lib/tier-colors";
import type { RemediationGuidance } from "@/types/api";

interface Props {
  guidance: RemediationGuidance[];
  isLoading: boolean;
}

const COLUMNS: Array<{ tier: string; label: string }> = [
  { tier: "CRITICAL", label: "Critical" },
  { tier: "HIGH", label: "High" },
  { tier: "MEDIUM", label: "Medium" },
  { tier: "LOW", label: "Low" },
];

export function RemediationBoard({ guidance, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {COLUMNS.map((c) => (
          <Skeleton key={c.tier} className="h-80 rounded-lg" />
        ))}
      </div>
    );
  }

  const byTier = COLUMNS.reduce<Record<string, RemediationGuidance[]>>((acc, { tier }) => {
    acc[tier] = guidance.filter((g) => g.tier === tier);
    return acc;
  }, {});

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {COLUMNS.map(({ tier, label }) => (
        <div key={tier} className="flex flex-col gap-2">
          {/* Column header */}
          <div
            className="flex items-center justify-between rounded-md px-3 py-2 text-xs font-bold uppercase tracking-wider text-white"
            style={{ backgroundColor: TIER_HEX[tier] }}
          >
            <span>{label}</span>
            <span className="rounded-full bg-white/20 px-1.5 py-0.5 text-[10px]">
              {byTier[tier].length}
            </span>
          </div>

          {/* Cards */}
          <div className="space-y-2 min-h-[200px]">
            {byTier[tier].length === 0 && (
              <p className="px-1 text-xs text-muted-foreground">No items</p>
            )}
            {byTier[tier].map((item) => (
              <RemediationItem key={item.cluster_id} item={item} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
