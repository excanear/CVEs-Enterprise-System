"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { STATUS_COLOR } from "@/lib/tier-colors";
import { cn } from "@/lib/utils";
import type { AnalysisSession } from "@/types/api";

interface Props {
  sessions: AnalysisSession[];
  isLoading: boolean;
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function SessionTimeline({ sessions, isLoading, selectedId, onSelect }: Props) {
  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full rounded-lg" />
        ))}
      </div>
    );
  }

  if (sessions.length === 0) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
        No analysis sessions
      </div>
    );
  }

  return (
    <div className="space-y-2 overflow-y-auto max-h-[600px] pr-1">
      {sessions.map((s) => (
        <div
          key={s.session_id}
          role="button"
          onClick={() => onSelect(s.session_id)}
          className={cn(
            "rounded-lg border p-3 cursor-pointer transition-colors hover:bg-accent",
            selectedId === s.session_id && "border-primary bg-primary/5"
          )}
        >
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-mono truncate text-foreground flex-1">
              {s.target_url}
            </p>
            <Badge
              className={cn("text-xs", STATUS_COLOR[s.status])}
              variant="outline"
            >
              {s.status}
            </Badge>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {new Date(s.created_at).toLocaleString()}
            {s.duration_seconds != null && ` · ${s.duration_seconds.toFixed(1)}s`}
          </p>
        </div>
      ))}
    </div>
  );
}
