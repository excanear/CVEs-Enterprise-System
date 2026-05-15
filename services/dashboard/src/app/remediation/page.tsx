"use client";

import { useRemediation } from "@/hooks/useRemediation";
import { RemediationBoard } from "@/components/remediation/RemediationBoard";
import { CompliancePillars } from "@/components/remediation/CompliancePillars";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

export default function RemediationPage() {
  const { guidance, compliance, isLoading } = useRemediation();

  const totalSteps = guidance.reduce((acc, g) => acc + g.steps.length, 0);
  const aiEnriched = guidance.filter((g) => g.llm_enriched).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Remediation Tracking</h1>
        <p className="text-sm text-muted-foreground mt-1">
          AI-generated remediation steps organized by severity tier
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          ["Total Items", guidance.length],
          ["Total Steps", totalSteps],
          ["AI-Enriched", aiEnriched],
        ].map(([label, val]) => (
          <Card key={label}>
            <CardContent className="pt-4 pb-4 text-center">
              <p className="text-2xl font-bold tabular-nums">{val}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-4">
        {/* Kanban board */}
        <div className="xl:col-span-3">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Remediation Board</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="grid grid-cols-4 gap-4">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-64" />
                  ))}
                </div>
              ) : (
                <RemediationBoard guidance={guidance} isLoading={false} />
              )}
            </CardContent>
          </Card>
        </div>

        {/* Compliance sidebar */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Compliance Pillars</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-12" />
                ))}
              </div>
            ) : (
              <CompliancePillars findings={compliance} />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
