import { afterEach, describe, expect, it, vi } from "vitest";

import { createAlias } from "../src/lib/api";

describe("one-click email aliases", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("asks the server for an alias labelled with the site, using the extension's token", async () => {
    await chrome.storage.session.set({ accessToken: { token: "tok", expiresAt: Date.now() + 60_000 } });
    const calls: { url: string; init: RequestInit }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        calls.push({ url, init });
        return new Response(JSON.stringify({ id: "1", address: "k7x2mq9p4h@relay.example.org", label: "shop.example", paused: false }), { status: 201 });
      }),
    );
    const alias = await createAlias("https://qalaa.test", "shop.example");
    expect(alias.address).toBe("k7x2mq9p4h@relay.example.org");
    expect(calls[0]!.url).toBe("https://qalaa.test/api/v1/extension/aliases");
    expect(calls[0]!.init.method).toBe("POST");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ label: "shop.example" });
    expect(new Headers(calls[0]!.init.headers).get("Authorization")).toBe("Bearer tok");
  });

  it("passes the server's reason on (not linked, no domain, limit)", async () => {
    await chrome.storage.session.set({ accessToken: { token: "tok", expiresAt: Date.now() + 60_000 } });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "not_linked", message: "Link this to your Qalaa account first." } }), { status: 409 })),
    );
    await expect(createAlias("https://qalaa.test", "x.example")).rejects.toThrow("Link this to your Qalaa account first.");
  });
});
