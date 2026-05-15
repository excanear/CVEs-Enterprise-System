"use client";

import { use } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { useEvidenceDetail } from "@/hooks/useEvidenceDetail";
import { EvidenceTimeline } from "@/components/evidence/EvidenceTimeline";
import { ConfidenceGauge } from "@/components/evidence/ConfidenceGauge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

interface PageProps {
  params: Promise<{ jobId: string }>;
}

export default function EvidenceDetailPage({ params }: PageProps) {
  const { jobId } = use(params);
  const { evidence, isLoading, isError } = useEvidenceDetail(jobId);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          href="/evidence"
          className="text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold">Evidence Detail</h1>
          <p className="font-mono text-xs text-muted-foreground mt-0.5">{jobId}</p>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 px-4 py-3 text-sm text-red-400">
          Failed to load evidence for job <span className="font-mono">{jobId}</span>
        </div>
      )}

      {isLoading ? (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-4">
          <Skeleton className="h-48 rounded-lg" />
          <div className="xl:col-span-3">
            <Skeleton className="h-[500px] rounded-lg" />
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Confidence</CardTitle>
            </CardHeader>
            <CardContent className="flex justify-center pt-0">
              <ConfidenceGauge evidence={evidence} threshold={0.75} />
            </CardContent>
          </Card>

          <Card className="xl:col-span-3">
            <CardHeader>
              <CardTitle className="text-base">4-Stage Evidence Breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              <EvidenceTimeline evidence={evidence} />
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
