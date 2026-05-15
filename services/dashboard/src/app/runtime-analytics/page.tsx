"use client";

import { useState } from "react";
import { useRuntimeAnalytics } from "@/hooks/useRuntimeAnalytics";
import { SessionTimeline } from "@/components/runtime-analytics/SessionTimeline";
import { APIInventory } from "@/components/runtime-analytics/APIInventory";
import { FrameworkBadges } from "@/components/runtime-analytics/FrameworkBadges";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function RuntimeAnalyticsPage() {
  const { sessions, isLoading } = useRuntimeAnalytics();
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Runtime Analytics</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Browser-intercepted APIs, frameworks, and WebSocket endpoints
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* Session list */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Analysis Sessions
              <span className="ml-2 text-sm font-normal text-muted-foreground">
                ({sessions.length})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <SessionTimeline
              sessions={sessions}
              isLoading={isLoading}
              selectedId={selectedSessionId}
              onSelect={setSelectedSessionId}
            />
          </CardContent>
        </Card>

        {/* Detail panel */}
        <div className="xl:col-span-2 space-y-4">
          {selectedSessionId && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Detected Frameworks & Metrics</CardTitle>
              </CardHeader>
              <CardContent>
                <FrameworkBadges sessionId={selectedSessionId} />
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Intercepted API Inventory</CardTitle>
            </CardHeader>
            <CardContent>
              <APIInventory sessionId={selectedSessionId} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
