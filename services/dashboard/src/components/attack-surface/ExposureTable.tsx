"use client";

import { useState } from "react";
import { ArrowUpDown } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { TierBadge } from "@/components/layout/TierBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { TIER_ORDER } from "@/lib/tier-colors";
import type { ExposurePrioritized } from "@/types/api";

interface Props {
  exposures: ExposurePrioritized[];
  isLoading: boolean;
}

type SortKey = "composite_score" | "tier" | "exposure_type";

export function ExposureTable({ exposures, isLoading }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("composite_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [tierFilter, setTierFilter] = useState<string>("ALL");

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  const filtered =
    tierFilter === "ALL" ? exposures : exposures.filter((e) => e.tier === tierFilter);

  const sorted = [...filtered].sort((a, b) => {
    let cmp = 0;
    if (sortKey === "composite_score") cmp = a.composite_score - b.composite_score;
    else if (sortKey === "tier") cmp = TIER_ORDER[a.tier] - TIER_ORDER[b.tier];
    else cmp = a.exposure_type.localeCompare(b.exposure_type);
    return sortDir === "asc" ? cmp : -cmp;
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full rounded" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Tier filter */}
      <div className="flex gap-2">
        {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((t) => (
          <Button
            key={t}
            variant={tierFilter === t ? "default" : "outline"}
            size="sm"
            onClick={() => setTierFilter(t)}
            className="text-xs"
          >
            {t}
          </Button>
        ))}
        <span className="ml-auto self-center text-xs text-muted-foreground">
          {sorted.length} exposures
        </span>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target URL</TableHead>
              <TableHead>
                <button
                  onClick={() => toggleSort("exposure_type")}
                  className="flex items-center gap-1 hover:text-foreground"
                >
                  Type <ArrowUpDown className="h-3 w-3" />
                </button>
              </TableHead>
              <TableHead>
                <button
                  onClick={() => toggleSort("tier")}
                  className="flex items-center gap-1 hover:text-foreground"
                >
                  Tier <ArrowUpDown className="h-3 w-3" />
                </button>
              </TableHead>
              <TableHead className="text-right">
                <button
                  onClick={() => toggleSort("composite_score")}
                  className="flex items-center justify-end gap-1 hover:text-foreground w-full"
                >
                  Score <ArrowUpDown className="h-3 w-3" />
                </button>
              </TableHead>
              <TableHead>Rationale</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                  No exposures found
                </TableCell>
              </TableRow>
            )}
            {sorted.map((exp) => (
              <TableRow key={exp.exposure_id}>
                <TableCell className="font-mono text-xs max-w-[220px] truncate">
                  {exp.target_url}
                </TableCell>
                <TableCell className="text-xs">{exp.exposure_type.replace(/_/g, " ")}</TableCell>
                <TableCell>
                  <TierBadge tier={exp.tier} />
                </TableCell>
                <TableCell className="text-right font-mono text-sm font-semibold">
                  {(exp.composite_score * 100).toFixed(0)}%
                </TableCell>
                <TableCell className="text-xs text-muted-foreground max-w-[280px] truncate">
                  {exp.rationale}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
