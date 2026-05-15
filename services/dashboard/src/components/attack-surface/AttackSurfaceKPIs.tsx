"use client";

import { ShieldAlert, AlertTriangle, Activity, TrendingDown } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { TIER_HEX } from "@/lib/tier-colors";
import type { RiskSummary } from "@/types/api";

interface Props {
  data: RiskSummary | undefined;
  isLoading: boolean;
}

const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const TIER_ICONS = {
  CRITICAL: ShieldAlert,
  HIGH: AlertTriangle,
  MEDIUM: Activity,
  LOW: TrendingDown,
};

export function AttackSurfaceKPIs({ data, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {TIERS.map((t) => (
          <Skeleton key={t} className="h-28 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {TIERS.map((tier) => {
        const count = data?.tier_breakdown?.[tier] ?? 0;
        const Icon = TIER_ICONS[tier];
        const color = TIER_HEX[tier];

        return (
          <Card
            key={tier}
            className="relative overflow-hidden border-l-4"
            style={{ borderLeftColor: color }}
          >
            <CardContent className="pt-5 pb-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">
                    {tier}
                  </p>
                  <p className="mt-1 text-3xl font-bold tabular-nums" style={{ color }}>
                    {count}
                  </p>
                </div>
                <Icon className="h-8 w-8 opacity-20" style={{ color }} />
              </div>
              {data && (
                <p className="mt-3 text-xs text-muted-foreground">
                  of {data.total_exposures} total exposures
                </p>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
