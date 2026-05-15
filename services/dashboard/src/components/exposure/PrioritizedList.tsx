"use client";

import { TierBadge, TierDot } from "@/components/layout/TierBadge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { TIER_ORDER } from "@/lib/tier-colors";
import type { ExposurePrioritized } from "@/types/api";

interface Props {
  exposures: ExposurePrioritized[];
  isLoading: boolean;
}

export function PrioritizedList({ exposures, isLoading }: Props) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  const sorted = [...exposures].sort(
    (a, b) =>
      TIER_ORDER[a.tier] - TIER_ORDER[b.tier] ||
      b.composite_score - a.composite_score
  );

  return (
    <div className="overflow-auto rounded-lg border max-h-[480px]">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8">#</TableHead>
            <TableHead>Tier</TableHead>
            <TableHead>URL</TableHead>
            <TableHead>Type</TableHead>
            <TableHead className="text-right w-24">Score</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sorted.map((exp, idx) => (
            <TableRow key={exp.exposure_id}>
              <TableCell className="text-xs text-muted-foreground tabular-nums">
                {idx + 1}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <TierDot tier={exp.tier} />
                  <TierBadge tier={exp.tier} />
                </div>
              </TableCell>
              <TableCell className="font-mono text-xs max-w-[200px] truncate">
                {exp.target_url}
              </TableCell>
              <TableCell className="text-xs">{exp.exposure_type.replace(/_/g, " ")}</TableCell>
              <TableCell className="text-right font-mono text-sm font-bold tabular-nums">
                {(exp.composite_score * 100).toFixed(0)}%
              </TableCell>
            </TableRow>
          ))}
          {sorted.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                No exposures
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
