"use client";

import { useState } from "react";
import Link from "next/link";
import { useTenant } from "@/app/providers";
import { useValidationJobs } from "@/hooks/useEvidenceDetail";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { STATUS_COLOR } from "@/lib/tier-colors";
import { cn } from "@/lib/utils";
import { ExternalLink } from "lucide-react";

export default function EvidencePage() {
  const { tenantId } = useTenant();
  const { data: jobs, isLoading } = useValidationJobs(tenantId);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Evidence Viewer</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Validation jobs with 4-stage evidence breakdown
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>URL</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-24 text-right">Duration</TableHead>
                <TableHead className="w-8" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(jobs ?? []).map((job) => (
                <TableRow key={job.job_id} className="group">
                  <TableCell className="font-mono text-xs max-w-xs truncate">
                    {job.target_url}
                  </TableCell>
                  <TableCell className="text-xs">{job.exposure_type.replace(/_/g, " ")}</TableCell>
                  <TableCell>
                    <span className={cn("text-xs font-semibold", STATUS_COLOR[job.status])}>
                      {job.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-right text-xs tabular-nums text-muted-foreground">
                    {job.duration_seconds != null ? `${job.duration_seconds.toFixed(1)}s` : "—"}
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/evidence/${job.job_id}`}
                      className="invisible group-hover:visible text-muted-foreground hover:text-foreground"
                    >
                      <ExternalLink className="h-3.5 w-3.5" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
              {(jobs ?? []).length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground py-10">
                    No validation jobs — submit a scan to generate evidence
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
