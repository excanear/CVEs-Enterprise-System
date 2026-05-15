"use client";

import React, { createContext, useContext, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

// ── Tenant context ──────────────────────────────────────────────────────────
interface TenantCtx {
  tenantId: string;
  setTenantId: (id: string) => void;
}

const TenantContext = createContext<TenantCtx>({
  tenantId: "dev-tenant",
  setTenantId: () => {},
});

export const useTenant = () => useContext(TenantContext);

// ── QueryClient singleton ───────────────────────────────────────────────────
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 25_000,
      refetchInterval: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// ── Providers ───────────────────────────────────────────────────────────────
export function Providers({ children }: { children: React.ReactNode }) {
  const [tenantId, setTenantId] = useState(
    () => process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID ?? "dev-tenant"
  );

  return (
    <TenantContext.Provider value={{ tenantId, setTenantId }}>
      <QueryClientProvider client={queryClient}>
        {children}
        <ReactQueryDevtools initialIsOpen={false} buttonPosition="bottom-left" />
      </QueryClientProvider>
    </TenantContext.Provider>
  );
}
