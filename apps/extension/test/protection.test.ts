import { getCredentials } from "../src/lib/api";
import { MAX_CHECKS_PER_MINUTE, assessDownload, assessUrl, resetThrottle } from "../src/lib/protection";
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
  await enrolled();
});

describe("assessUrl", () => {
  it("does nothing while paused or for non-web addresses", async () => {
    const fetchMock = serve(() => json(verdict("no_known_threat")));
    expect(await assessUrl("https://example.com/", { ...settings, paused: true })).toBeNull();
    expect(await assessUrl("chrome://extensions", settings)).toBeNull();
    expect(await assessUrl("http://192.168.0.1/", settings)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("applies the user's lists without contacting the server", async () => {
    const fetchMock = serve(() => json(verdict("dangerous")));
    expect((await assessUrl("https://ads.blocked.test/", { ...settings, blocklist: ["blocked.test"] }))?.verdict).toBe("blocked_by_you");
    expect((await assessUrl("https://intranet.allowed.test/", { ...settings, allowlist: ["allowed.test"] }))?.verdict).toBe("allowed_by_you");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("authenticates, caches and shares concurrent lookups", async () => {
    const fetchMock = serve(() => json(verdict("dangerous")));
    const [first, second] = await Promise.all([
      assessUrl("https://example.com/a", settings),
      assessUrl("https://example.com/a", settings),
    ]);
    const third = await assessUrl("https://example.com/a", settings);
    expect(first?.verdict).toBe("dangerous");
    expect(second).toEqual(first);
    expect(third).toEqual(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${SERVER}/api/v1/extension/check-url`);
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer access-1");
    expect(init.credentials).toBe("omit");
  });

  it("sends only the domain in privacy mode", async () => {
    const fetchMock = serve(() => json(verdict("no_known_threat")));
    await assessUrl("https://example.com/private/path?q=1", { ...settings, privacyMode: "host" });
    expect(JSON.parse(fetchMock.mock.calls[0]![1].body as string)).toEqual({ url: "https://example.com/", mode: "host" });
  });

  it("reports the check as unavailable when the server cannot be reached", async () => {
    serve(() => {
      throw new TypeError("Failed to fetch");
    });
    const result = await assessUrl("https://example.org/", settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/could not be reached/);
  });

  it("refreshes an expired access token once and retries", async () => {
    const fetchMock = serve((url, init) => {
      if (url.endsWith("/extension/token")) return json({ access_token: "access-2", expires_in: 900 });
      const token = (init.headers as Record<string, string>).Authorization;
      return token === "Bearer access-2" ? json(verdict("no_known_threat")) : json({ error: { code: "extension_unauthorized" } }, 401);
    });
    expect((await assessUrl("https://example.net/", settings))?.verdict).toBe("no_known_threat");
    expect(fetchMock.mock.calls.map(([url]) => url.split("/v1")[1])).toEqual(["/extension/check-url", "/extension/token", "/extension/check-url"]);
  });

  it("forgets credentials revoked from the dashboard", async () => {
    serve((url) => json({ error: { code: "extension_unauthorized" } }, 401));
    const result = await assessUrl("https://example.io/", settings);
    expect(result?.verdict).toBe("unavailable");
    expect(result?.limitations[0]).toMatch(/disconnected/);
    expect(await getCredentials()).toBeNull();
  });

  it("stops querying the server above the rate ceiling", async () => {
    const fetchMock = serve(() => json(verdict("no_known_threat")));
    const results = [];
    for (let n = 0; n <= MAX_CHECKS_PER_MINUTE; n += 1) results.push(await assessUrl(`https://site${n}.example/`, settings));
    expect(fetchMock).toHaveBeenCalledTimes(MAX_CHECKS_PER_MINUTE);
    expect(results.at(-1)?.verdict).toBe("unavailable");
  });
});

describe("assessDownload", () => {
  it("respects the download setting and sends the file name", async () => {
    const fetchMock = serve(() => json(verdict("suspicious")));
    expect(await assessDownload("https://example.com/f", "invoice.pdf.exe", { ...settings, downloadChecks: false })).toBeNull();
    const result = await assessDownload("https://example.com/f", "invoice.pdf.exe", settings);
    expect(result?.verdict).toBe("suspicious");
    expect(JSON.parse(fetchMock.mock.calls[0]![1].body as string)).toEqual({ url: "https://example.com/f", filename: "invoice.pdf.exe" });
  });
});
