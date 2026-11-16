import { vi } from "vitest";

import type { Scan } from "@/lib/api/types";

export function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "6f1c2a1e-0000-4000-8000-000000000001",
    scan_type: "url",
    status: "completed",
    target: "https://example.org/",
    risk: "no_known_threat",
    confidence: "medium",
    summary: "No known threat was detected in this link.",
    findings: [],
    checks: [
      {
        key: "local_threat_feed",
        label: "Known malicious links",
        provider: "URLhaus feed (local copy)",
        status: "completed",
        detail: "Compared against 120 indicators.",
        core: true,
        finished_at: "2026-11-16T10:00:01Z",
      },
    ],
    details: { submitted_url: "https://example.org/", final_url: "https://example.org/" },
    recommendations: ["No known threat was found, which is not a guarantee."],
    limitations: ["Page content was not downloaded or inspected."],
    error: null,
    created_at: "2026-11-16T10:00:00Z",
    started_at: "2026-11-16T10:00:00Z",
    completed_at: "2026-11-16T10:00:02Z",
    saved_to_history: false,
    ...overrides,
  };
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Replace fetch with a queue of canned responses, returned in order. */
export function mockFetch(...responses: (Response | Error)[]) {
  const fetchMock = vi.fn<(url: string, init?: RequestInit) => Promise<Response>>(async () => {
    const next = responses.length > 1 ? responses.shift() : responses[0];
    if (!next) throw new Error("No mocked response left");
    if (next instanceof Error) throw next;
    return next.clone();
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}
