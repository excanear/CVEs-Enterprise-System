"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { TIER_HEX } from "@/lib/tier-colors";
import type { ExposurePrioritized } from "@/types/api";

interface Props {
  exposures: ExposurePrioritized[];
}

// Derive synthetic trend buckets from recorded_at timestamps
// Groups exposures by exposure_type and counts per tier
function buildChartData(exposures: ExposurePrioritized[]) {
  const typeCounts: Record<string, Record<string, number>> = {};
  exposures.forEach((e) => {
    if (!typeCounts[e.exposure_type]) {
      typeCounts[e.exposure_type] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    }
    typeCounts[e.exposure_type][e.tier] = (typeCounts[e.exposure_type][e.tier] ?? 0) + 1;
  });

  return Object.entries(typeCounts)
    .map(([type, counts]) => ({
      type: type.replace(/_/g, " ").slice(0, 20),
      ...counts,
    }))
    .slice(0, 12);
}

const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

export function ExposureTrendChart({ exposures }: Props) {
  const data = buildChartData(exposures);

  if (data.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
        No exposure data
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data} margin={{ top: 4, right: 16, left: 0, bottom: 60 }}>
        <defs>
          {TIERS.map((tier) => (
            <linearGradient key={tier} id={`grad-${tier}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={TIER_HEX[tier]} stopOpacity={0.25} />
              <stop offset="95%" stopColor={TIER_HEX[tier]} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 19% 20%)" />
        <XAxis
          dataKey="type"
          tick={{ fill: "hsl(215 20% 55%)", fontSize: 10 }}
          angle={-35}
          textAnchor="end"
          interval={0}
        />
        <YAxis tick={{ fill: "hsl(215 20% 55%)", fontSize: 11 }} allowDecimals={false} />
        <Tooltip
          contentStyle={{
            backgroundColor: "hsl(222 47% 10%)",
            border: "1px solid hsl(217 19% 20%)",
            borderRadius: 6,
            fontSize: 12,
          }}
        />
        <Legend wrapperStyle={{ fontSize: 11, paddingTop: 8 }} />
        {TIERS.map((tier) => (
          <Area
            key={tier}
            type="monotone"
            dataKey={tier}
            stroke={TIER_HEX[tier]}
            fill={`url(#grad-${tier})`}
            strokeWidth={2}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
