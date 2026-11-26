import { getCredentials, reportEvent } from "../src/lib/api";
import { resetLocalCheck, sha256Hex } from "../src/lib/local-check";
import { MAX_CHECKS_PER_MINUTE, assessDownload, assessUrl, assessUrlOnServer, resetThrottle } from "../src/lib/protection";
import { DEFAULT_SETTINGS, type Settings } from "../src/lib/settings";

const SERVER = "https://sentinel.test";
const settings: Settings = { ...DEFAULT_SETTINGS, serverUrl: SERVER };

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function verdict(name: string, host = "example.com") {
  return {
    verdict: name,
    host,
    reasons: name === "dangerous" ? [{ severity: "critical", title: "Listed by URLhaus", explanation: "x", source: "URLhaus", evidence: {} }] : [],
    sources: ["URLhaus"],
    limitations: [],
    checked_at: "2026-11-16T10:00:00Z",
    cache_seconds: 1800,
  };
}

async function enrolled() {
  await chrome.storage.local.set({ credentials: { installationId: "i1", refreshToken: "refresh-1" } });
  await chrome.storage.session.set({ accessToken: { token: "access-1", expiresAt: Date.now() + 600_000 } });
}

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

function serve(handler: Handler) {
  const fetchMock = vi.fn(async (url: string, init: RequestInit) => handler(url, init));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

beforeEach(async () => {
  resetThrottle();
  resetLocalCheck();
  await enrolled();
});

/** Stores a downloaded prefix list holding the prefixes of these values plus some filler. */
async function storeList(values: string[], sources = ["URLhaus", "ThreatFox"]) {
  const prefixes = new Set<string>(["00000001", "7fffffff", "fffffff0"]);
  for (const value of values) prefixes.add((await sha256Hex(value)).slice(0, 8));
  const bytes = [...prefixes].sort().flatMap((hex) => hex.match(/../g)!.map((b) => parseInt(b, 16)));
  await chrome.storage.local.set({
    threatPrefixes: { version: "v1", prefixes: btoa(String.fromCharCode(...bytes)), count: prefixes.size, sources, fetchedAt: new Date().toISOString() },
  });
}

describe("assessUrl (checked inside the browser)", () => {
  it("does nothing while paused or for non-web addresses", async () => {
    const fetchMock = serve(() => json({}));
    expect(await assessUrl("https://example.com/", { ...settings, paused: true })).toBeNull();
    expect(await assessUrl("chrome://extensions", settings)).toBeNull();
    expect(await assessUrl("http://192.168.0.1/", settings)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("applies the user's lists without contacting the server", async () => {
    const fetchMock = serve(() => json({}));
    expect((await assessUrl("https://ads.blocked.test/", { ...settings, blocklist: ["blocked.test"] }))?.verdict).toBe("blocked_by_you");
    expect((await assessUrl("https://intranet.allowed.test/", { ...settings, allowlist: ["allowed.test"] }))?.verdict).toBe("allowed_by_you");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never sends the address: an unlisted page is answered from the local list", async () => {
    const fetchMock = serve(() => json({}));
    await storeList(["https://listed.example/bad"]);
    const result = await assessUrl("https://example.com/private/path?q=1", settings);
    expect(result?.verdict).toBe("no_known_threat");
    expect(result?.sources).toContain("URLhaus");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("finds look-alike domains with no network at all", async () => {
    const fetchMock = serve(() => json({}));
    const result = await assessUrl("https://paypa1.com/login", settings);
    expect(result?.verdict).toBe("suspicious");
    expect(result?.reasons[0]?.title).toMatch(/look-alike of “paypal”/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("says a clean result can't be confirmed without a recent list", async () => {
    serve(() => json({}));
    const result = await assessUrl("https://example.org/", settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/hasn't been downloaded recently/);
  });

  it("on a prefix match, asks for full hashes with decoys and compares them locally", async () => {
    const listed = "http://malware.example.net/payload.exe";
    const digest = await sha256Hex(listed);
    const fetchMock = serve(() => json({ matches: [{ digest, kind: "url", source: "urlhaus", source_name: "URLhaus", threat: "malware_download" }] }));
    await storeList([listed]);
    const result = await assessUrl(listed, settings);
    expect(result?.verdict).toBe("dangerous");
    expect(result?.reasons[0]?.title).toBe("This exact link is listed by URLhaus");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${SERVER}/api/v1/extension/threat-hashes`);
    const sent = JSON.parse(init.body as string) as { prefixes: string[] };
    expect(sent.prefixes).toContain(digest.slice(0, 8));
    expect(sent.prefixes.length).toBeGreaterThan(1); // decoys from the list
    expect(init.body as string).not.toContain("malware.example.net");
    // A second visit uses the cached hashes.
    await assessUrl(`${listed}`, settings);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("ignores a prefix collision whose full hash differs", async () => {
    const page = "https://example.com/";
    const prefix = (await sha256Hex(page)).slice(0, 8);
    serve(() => json({ matches: [{ digest: `${prefix}${"0".repeat(56)}`, kind: "url", source: "urlhaus", source_name: "URLhaus", threat: null }] }));
    await storeList([page]);
    expect((await assessUrl(page, settings))?.verdict).toBe("no_known_threat");
  });

  it("finds a listed domain from a subdomain", async () => {
    const digest = await sha256Hex("evil.example");
    serve(() => json({ matches: [{ digest, kind: "host", source: "community", source_name: "Qalaa community reports", threat: null }] }));
    await storeList(["evil.example"]);
    const result = await assessUrl("https://login.evil.example/", settings);
    expect(result?.verdict).toBe("suspicious");
    expect(result?.reasons[0]?.title).toBe("This website was reported by Qalaa users as a scam");
  });

  it("reports an unconfirmed match when the hash lookup fails", async () => {
    const listed = "https://listed.example/";
    serve(() => {
      throw new TypeError("Failed to fetch");
    });
    await storeList([listed]);
    const result = await assessUrl(listed, settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/may be on the list of known threats/);
  });

  it("stops checking above the rate ceiling", async () => {
    serve(() => json({}));
    await storeList([]);
    const results = [];
    for (let n = 0; n <= MAX_CHECKS_PER_MINUTE; n += 1) results.push(await assessUrl(`https://site${n}.example/`, settings));
    expect(results.at(-2)?.verdict).toBe("no_known_threat");
    expect(results.at(-1)?.verdict).toBe("unavailable");
  });
});

describe("assessUrlOnServer (only when the person asks)", () => {
  it("authenticates, sends the full address, caches and shares concurrent lookups", async () => {
    const fetchMock = serve(() => json(verdict("dangerous")));
    const [first, second] = await Promise.all([
      assessUrlOnServer("https://example.com/a", settings),
      assessUrlOnServer("https://example.com/a", settings),
    ]);
    const third = await assessUrlOnServer("https://example.com/a", settings);
    expect(first?.verdict).toBe("dangerous");
    expect(second).toEqual(first);
    expect(third).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${SERVER}/api/v1/extension/check-url`);
    expect(JSON.parse(init.body as string)).toEqual({ url: "https://example.com/a", mode: "full" });
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer access-1");
    expect(init.credentials).toBe("omit");
  });

  it("reports the check as unavailable when the server cannot be reached", async () => {
    serve(() => {
      throw new TypeError("Failed to fetch");
    });
    const result = await assessUrlOnServer("https://example.org/", settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/could not be reached/);
  });

  it("refreshes an expired access token once and retries", async () => {
    const fetchMock = serve((url, init) => {
      if (url.endsWith("/extension/token")) return json({ access_token: "access-2", expires_in: 900 });
      const token = (init.headers as Record<string, string>).Authorization;
      return token === "Bearer access-2" ? json(verdict("no_known_threat")) : json({ error: { code: "extension_unauthorized" } }, 401);
    });
    expect((await assessUrlOnServer("https://example.net/", settings))?.verdict).toBe("no_known_threat");
    expect(fetchMock.mock.calls.map(([url]) => url.split("/v1")[1])).toEqual(["/extension/check-url", "/extension/token", "/extension/check-url"]);
  });

  it("forgets credentials revoked from the dashboard", async () => {
    serve(() => json({ error: { code: "extension_unauthorized" } }, 401));
    const result = await assessUrlOnServer("https://example.io/", settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/disconnected/);
    expect(await getCredentials()).toBeNull();
  });
});

describe("assessDownload", () => {
  it("respects the download setting and checks the file name locally", async () => {
    const fetchMock = serve(() => json({}));
    await storeList([]);
    expect(await assessDownload("https://example.com/f", "invoice.pdf.exe", { ...settings, downloadChecks: false })).toBeNull();
    const result = await assessDownload("https://example.com/f", "invoice.pdf.exe", settings);
    expect(result?.verdict).toBe("suspicious");
    expect(result?.reasons[0]?.title).toMatch(/disguises a program/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("reportEvent", () => {
  it("sends only the site, never the path or query", async () => {
    const fetchMock = serve(() => json({ stored: true }));
    await reportEvent(SERVER, { kind: "warning_shown", url: "https://evil.example/login?token=secret", verdict: "dangerous" });
    expect(JSON.parse(fetchMock.mock.calls[0]![1].body as string)).toEqual({ kind: "warning_shown", url: "https://evil.example/", verdict: "dangerous" });
  });
});
