import { NextResponse, type NextRequest } from "next/server";

import { shareDestination } from "@/lib/share";

/**
 * Receives content shared from another app (Web Share Target) and opens the right
 * scanner with it filled in. Nothing is submitted until the person confirms.
 */
export function GET(request: NextRequest) {
  return NextResponse.redirect(new URL(shareDestination(request.nextUrl.searchParams), request.nextUrl.origin), 303);
}
