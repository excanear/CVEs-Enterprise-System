"use client";

import { RefreshCw } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useTenant } from "@/app/providers";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function TopBar() {
  const { tenantId, setTenantId } = useTenant();
  const queryClient = useQueryClient();

  function refreshAll() {
    queryClient.invalidateQueries();
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-card px-6">
      <div className="flex items-center gap-3">
        <label className="text-xs font-medium text-muted-foreground whitespace-nowrap">
          Tenant ID
        </label>
        <Input
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value)}
          className="h-7 w-72 font-mono text-xs"
          placeholder="00000000-0000-0000-0000-000000000001"
        />
      </div>

      <Button variant="ghost" size="sm" onClick={refreshAll} title="Refresh all data">
        <RefreshCw className="h-4 w-4 mr-1.5" />
        Refresh
      </Button>
    </header>
  );
}
