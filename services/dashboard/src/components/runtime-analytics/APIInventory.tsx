"use client";

import { useQuery } from "@tanstack/react-query";
import { raeApi } from "@/lib/api-client";
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
import type { InterceptedAPI } from "@/types/api";

const METHOD_COLOR: Record<string, string> = {
  GET: "text-blue-400",
  POST: "text-green-400",
  PUT: "text-yellow-400",
  PATCH: "text-orange-400",
  DELETE: "text-red-400",
};

interface Props {
  sessionId: string | null;
}

export function APIInventory({ sessionId }: Props) {
  const { data: apis, isLoading } = useQuery<InterceptedAPI[]>({
    queryKey: ["session-apis", sessionId],
    queryFn: () => raeApi.getApis(sessionId!) as Promise<InterceptedAPI[]>,
    enabled: !!sessionId,
    staleTime: 60_000,
  });

  if (!sessionId) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
        Select a session to view intercepted APIs
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="overflow-auto max-h-[600px] rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-20">Method</TableHead>
            <TableHead>URL</TableHead>
            <TableHead className="w-20 text-center">Status</TableHead>
            <TableHead className="w-20 text-center">GraphQL</TableHead>
            <TableHead>Params</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(!apis || apis.length === 0) && (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                No APIs found
              </TableCell>
            </TableRow>
          )}
          {apis?.map((api, idx) => (
            <TableRow key={idx}>
              <TableCell>
                <span className={`text-xs font-mono font-bold ${METHOD_COLOR[api.method] ?? ""}`}>
                  {api.method}
                </span>
              </TableCell>
              <TableCell className="font-mono text-xs max-w-xs truncate">{api.url}</TableCell>
              <TableCell className="text-center text-xs tabular-nums">
                {api.status_code ?? "—"}
              </TableCell>
              <TableCell className="text-center">
                {api.is_graphql ? (
                  <Badge variant="secondary" className="text-xs">GQL</Badge>
                ) : null}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {api.params.slice(0, 4).join(", ")}
                {api.params.length > 4 && ` +${api.params.length - 4}`}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
