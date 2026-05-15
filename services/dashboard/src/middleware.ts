import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Middleware: inject X-Tenant-ID on all /api/proxy/* requests.
 * In production replace the hardcoded default with JWT extraction via `jose`.
 */
export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // Only inject on proxy calls – pages don't need it server-side
  if (request.nextUrl.pathname.startsWith("/api/proxy/")) {
    const tenantId =
      request.cookies.get("tenant_id")?.value ??
      request.headers.get("x-tenant-id") ??
      process.env.NEXT_PUBLIC_DEFAULT_TENANT_ID ??
      "dev-tenant";

    response.headers.set("x-tenant-id", tenantId);
  }

  return response;
}

export const config = {
  matcher: ["/api/proxy/:path*"],
};
