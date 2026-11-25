import { describe, expect, it } from "vitest";

import { AliasService } from "../src/core/alias-service";
import { createHandlers } from "../src/core/handlers";
import { AccountLinkError, type LinkedAccount, createAlias } from "../src/engine/account";

const account: LinkedAccount = { deviceId: "d1", token: "device-token", email: "amira@example.com", server: "https://qalaa.test" };
const alias = { id: "a1", address: "k7x2mq9p4h@relay.example.org", label: null, paused: false, forwarded_count: 0, blocked_count: 0 };

describe("email aliases from the desktop", () => {
  it("calls the device endpoint with the device token", async () => {
    const calls: [string, RequestInit][] = [];
    const fetcher = (async (url: string, init: RequestInit) => {
      calls.push([url, init]);
      return new Response(JSON.stringify(alias), { status: 201 });
    }) as unknown as typeof fetch;
    expect((await createAlias(account, "news.example", fetcher)).address).toBe(alias.address);
    expect(calls[0]![0]).toBe("https://qalaa.test/api/v1/devices/aliases");
    expect((calls[0]![1].headers as Record<string, string>).Authorization).toBe("Bearer device-token");
    expect(JSON.parse(String(calls[0]![1].body))).toEqual({ label: "news.example" });
  });

  it("creates one, copies it when asked, and needs a linked account", async () => {
    const copied: string[] = [];
    const linked = new AliasService(async () => account, async (t) => void copied.push(t), {
      createAlias: async () => alias,
      listAliases: async () => ({ aliases: [alias], domains: ["relay.example.org"], forwards_to: "amira@example.com" }),
    });
    expect(await linked.create({ copy: true })).toMatchObject({ address: alias.address, copied: true });
    expect(copied).toEqual([alias.address]);
    expect((await linked.create({})).copied).toBe(false);
    expect((await linked.list()).aliases).toHaveLength(1);
    await expect(linked.create({ label: "x".repeat(200) })).rejects.toMatchObject({ code: "bad_params" });

    const unlinked = new AliasService(async () => null, null);
    await expect(unlinked.create({})).rejects.toMatchObject({ code: "not_linked" });
  });

  it("passes the server's reason on", async () => {
    const service = new AliasService(async () => account, null, {
      createAlias: async () => {
        throw new AccountLinkError("Verify your email address first: aliases forward to it.", 409);
      },
      listAliases: async () => {
        throw new TypeError("fetch failed");
      },
    });
    await expect(service.create({})).rejects.toMatchObject({ code: "unavailable", message: "Verify your email address first: aliases forward to it." });
    await expect(service.list()).rejects.toMatchObject({ code: "server_error" });
  });

  it("is reachable over IPC", async () => {
    const service = new AliasService(async () => account, null, { createAlias: async () => alias, listAliases: async () => ({ aliases: [], domains: [], forwards_to: null }) });
    const handlers = createHandlers({ version: "t", aliases: service, homeInput: async () => { throw new Error(); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} }, () => {});
    expect(await handlers["aliases.create"]!({})).toMatchObject({ address: alias.address });
    expect(await handlers["aliases.list"]!(undefined)).toEqual({ aliases: [], domains: [], forwards_to: null });
  });
});
