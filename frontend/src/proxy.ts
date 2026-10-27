import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Optimistic check only: sends visitors without a session cookie to /login.
// Real authorisation happens on every API request in the backend.
export function proxy(request: NextRequest) {
  if (!request.cookies.has("sf_session")) {
    const url = new URL("/login", request.url);
    const next = request.nextUrl.pathname + request.nextUrl.search;
    if (next !== "/") url.searchParams.set("next", next);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/incidents/:path*",
    "/alerts/:path*",
    "/events/:path*",
    "/investigations/:path*",
    "/threat-intel/:path*",
    "/detections/:path*",
    "/attack-coverage/:path*",
    "/playbooks/:path*",
    "/response-actions/:path*",
    "/reports/:path*",
    "/audit/:path*",
    "/settings/:path*",
  ],
};
