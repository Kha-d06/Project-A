/**
 * Same-origin gateway to the Qalaa API.
 *
 * Done here rather than with a next.config rewrite for two reasons: rewrites are
 * fixed at build time (so one image could not serve different environments), and
 * they pass a client-supplied X-Forwarded-For straight through, which would let
 * anyone pick the address the API rate-limits them by.
 *
 * Deployment assumption: this server is reachable only through the reverse proxy
 * (Caddy in docker-compose.yml), which replaces X-Forwarded-For with the real
 * client address. See docs/security.md.
 */

const API_ORIGIN = process.env.SENTINEL_API_URL ?? "http://localhost:8000";
const UPSTREAM_TIMEOUT_MS = 90_000;

const FORWARDED_REQUEST_HEADERS = [
  "accept",
  "accept-language",
  "authorization",
  "content-type",
  "content-length",
  "cookie",
  "x-csrf-token",
];
// Hop-by-hop headers and ones the runtime recomputes for the outgoing response.
const DROPPED_RESPONSE_HEADERS = new Set(["connection", "keep-alive", "transfer-encoding", "content-encoding", "content-length", "set-cookie"]);

function clientAddress(request: Request): string | null {
  const forwarded = request.headers.get("x-forwarded-for");
  return forwarded?.split(",")[0]?.trim() || null;
}

async function forward(request: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const incoming = new URL(request.url);
  const target = new URL(`/api/v1/${path.map(encodeURIComponent).join("/")}${incoming.search}`, API_ORIGIN);

  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  const address = clientAddress(request);
  if (address) headers.set("x-forwarded-for", address);
  headers.set("x-forwarded-proto", incoming.protocol.replace(":", ""));

  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      // Streams the upload instead of buffering it in this process.
      ...(hasBody ? { duplex: "half" } : {}),
    } as RequestInit);
  } catch {
    return Response.json(
      { error: { code: "service_unavailable", message: "The Qalaa service is unavailable right now. Please try again shortly.", details: null } },
      { status: 502 },
    );
  }

  const responseHeaders = new Headers();
  upstream.headers.forEach((value, name) => {
    if (!DROPPED_RESPONSE_HEADERS.has(name)) responseHeaders.set(name, value);
  });
  for (const cookie of upstream.headers.getSetCookie()) responseHeaders.append("set-cookie", cookie);

  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
}

export const dynamic = "force-dynamic";
export { forward as GET, forward as POST, forward as PUT, forward as PATCH, forward as DELETE };
