/**
 * Catch-all reverse proxy to all backend services.
 * URL pattern: /api/proxy/[service]/[...path]
 *
 * Supported services: rae | jsi | eve | age | acl | re | so
 */
import { type NextRequest, NextResponse } from "next/server";

const SERVICE_MAP: Record<string, string> = {
  rae: process.env.RAE_BASE_URL ?? "http://localhost:8004",
  jsi: process.env.JSI_BASE_URL ?? "http://localhost:8005",
  eve: process.env.EVE_BASE_URL ?? "http://localhost:8006",
  age: process.env.AGE_BASE_URL ?? "http://localhost:8007",
  acl: process.env.ACL_BASE_URL ?? "http://localhost:8008",
  re: process.env.RE_BASE_URL ?? "http://localhost:8009",
  so: process.env.SO_BASE_URL ?? "http://localhost:8003",
};

type RouteParams = { params: Promise<{ service: string; path: string[] }> };

async function proxyRequest(request: NextRequest, { params }: RouteParams) {
  const { service, path } = await params;
  const baseUrl = SERVICE_MAP[service];

  if (!baseUrl) {
    return NextResponse.json({ error: `Unknown service: ${service}` }, { status: 404 });
  }

  const searchParams = request.nextUrl.searchParams.toString();
  const targetPath = path.join("/");
  const targetUrl = `${baseUrl}/${targetPath}${searchParams ? `?${searchParams}` : ""}`;

  const tenantId =
    request.headers.get("x-tenant-id") ??
    request.cookies.get("tenant_id")?.value ??
    process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID ??
    "dev-tenant";

  const forwardHeaders: HeadersInit = {
    "X-Tenant-ID": tenantId,
    "Content-Type": request.headers.get("content-type") ?? "application/json",
  };
  const auth = request.headers.get("authorization");
  if (auth) forwardHeaders["Authorization"] = auth;

  const fetchOptions: RequestInit = {
    method: request.method,
    headers: forwardHeaders,
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await request.text();
    if (body) fetchOptions.body = body;
  }

  try {
    const upstream = await fetch(targetUrl, fetchOptions);
    const contentType = upstream.headers.get("content-type") ?? "application/json";

    // Stream-safe: use arrayBuffer to preserve binary (PDF, CSV) payloads
    const body = await upstream.arrayBuffer();

    return new NextResponse(body, {
      status: upstream.status,
      headers: {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Upstream unreachable";
    console.error(`[proxy] ${service} → ${targetUrl}:`, message);
    return NextResponse.json(
      { error: "Service unavailable", service, target: targetUrl },
      { status: 503 }
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;
