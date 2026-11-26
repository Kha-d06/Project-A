import { describe, expect, it, vi } from "vitest";

import type { LinkedAccount } from "../src/engine/account";
import { type RemoteHost, RemoteAgent, quarantineCandidates } from "../src/engine/remote";

const account: LinkedAccount = { deviceId: "d1", token: "sdv_test", email: "a@example.com", server: "https://sentinel.test" };

function fakeServer(commands: unknown[]) {
  const calls: { path: string; method: string; body: unknown; auth: string | null }[] = [];
  const fetcher = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname.replace("/api/v1", "");
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ path, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null, auth: headers.Authorization ?? null });
    if (path === "/devices/heartbeat") return Response.json({ pending_commands: commands.length });
    if (path === "/devices/commands") return Response.json(commands.splice(0));
    if (path === "/devices/wait") return Response.json({ pending: commands.length > 0 });
    return new Response(null, { status: 204 });
  });
  return { calls, fetcher: fetcher as unknown as typeof fetch };
}

function host(overrides: Partial<RemoteHost> = {}): RemoteHost {
  return {
    account: () => account,
    allowRemote: () => true,
    folders: () => [
      { id: "watch-0", label: "Downloads", path: "/home/me/Downloads" },
      { id: "documents", label: "Documents", path: "/home/me/Documents" },
    ],
    homeFolder: () => "/home/me",
    status: () => ({ protection: "watching" }),
    version: () => "1.0.0",
    scan: vi.fn(async () => ({
      scanned: 3,
      malicious: 1,
      suspicious: 0,
      quarantined: 0,
      detections: [{ name: "bad.exe", folder: "Documents", verdict: "malicious" as const, title: "Known malware", sha256: "a".repeat(64), quarantined: false }],
    })),
    quarantineByHash: vi.fn(async (hashes: string[]) => hashes.length),
    updateSignatures: vi.fn(async () => undefined),
    unlinked: vi.fn(),
    activity: vi.fn(),
    ...overrides,
  };
}

describe("remote agent", () => {
  it("sends folder ids and labels but never paths", async () => {
    const { calls, fetcher } = fakeServer([]);
    await new RemoteAgent(host(), fetcher).tick();
    const beat = calls[0]!;
    expect(beat.path).toBe("/devices/heartbeat");
    expect(beat.auth).toBe("Bearer sdv_test");
    expect(JSON.stringify(beat.body)).not.toContain("/home/me");
    expect(beat.body).toMatchObject({ allow_remote: true, folders: [{ id: "watch-0", label: "Downloads" }, { id: "documents", label: "Documents" }] });
  });

  it("runs a folder scan on the chosen folder and reports detections", async () => {
    const h = host();
    const { calls, fetcher } = fakeServer([{ id: "c1", kind: "folder_scan", args: { folder_id: "documents" } }]);
    await new RemoteAgent(h, fetcher).tick();
    expect(h.scan).toHaveBeenCalledWith([{ path: "/home/me/Documents", label: "Documents" }], expect.any(Function));
    expect(calls.map((c) => c.path)).toEqual(["/devices/heartbeat", "/devices/commands", "/devices/commands/c1/started", "/devices/commands/c1/result"]);
    expect(calls[3]!.body).toMatchObject({ ok: true, scanned: 3, malicious: 1, detections: [{ name: "bad.exe", folder: "Documents" }] });
    expect(JSON.stringify(calls[3]!.body)).not.toContain("/home/me");
  });

  it("refuses an unknown folder and scans nothing", async () => {
    const h = host();
    const { calls, fetcher } = fakeServer([{ id: "c2", kind: "folder_scan", args: { folder_id: "../../etc" } }]);
    await new RemoteAgent(h, fetcher).tick();
    expect(h.scan).not.toHaveBeenCalled();
    expect(calls.at(-1)!.body).toMatchObject({ ok: false });
  });

  it("refuses everything when remote scans were turned off", async () => {
    const h = host({ allowRemote: () => false });
    const { calls, fetcher } = fakeServer([{ id: "c3", kind: "full_scan", args: {} }]);
    await new RemoteAgent(h, fetcher).tick();
    expect(h.scan).not.toHaveBeenCalled();
    expect(calls.map((c) => c.path)).not.toContain("/devices/commands/c3/started");
    expect(calls.at(-1)!.body).toMatchObject({ ok: false });
  });

  it("quick scan covers watched folders only; quarantine passes only valid hashes", async () => {
    const h = host();
    const { fetcher } = fakeServer([
      { id: "c4", kind: "quick_scan", args: {} },
      { id: "c5", kind: "quarantine", args: { sha256: ["b".repeat(64), "not-a-hash"] } },
    ]);
    await new RemoteAgent(h, fetcher).tick();
    expect(h.scan).toHaveBeenCalledWith([{ path: "/home/me/Downloads", label: "Downloads" }], expect.any(Function));
    expect(h.quarantineByHash).toHaveBeenCalledWith(["b".repeat(64)]);
  });

  it("forgets the account when the server says the device was removed", async () => {
    const h = host();
    const fetcher = (async () => Response.json({ error: { message: "Unknown device" } }, { status: 401 })) as unknown as typeof fetch;
    const agent = new RemoteAgent(h, fetcher);
    await agent.tick();
    expect(h.unlinked).toHaveBeenCalled();
    expect(agent.lastError).toMatch(/removed/);
  });

  it("reports scan progress as counts only, at most every few seconds", async () => {
    const h = host({
      scan: vi.fn(async (_targets, onProgress) => {
        onProgress?.({ scanned: 1, found: 0, folder: "Home" });
        onProgress?.({ scanned: 2, found: 0, folder: "Home" }); // throttled
        return { scanned: 2, malicious: 0, suspicious: 0, quarantined: 0, detections: [] };
      }),
    });
    const { calls, fetcher } = fakeServer([{ id: "c9", kind: "full_scan", args: {} }]);
    await new RemoteAgent(h, fetcher).tick();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const progress = calls.filter((c) => c.path === "/devices/commands/c9/progress");
    expect(progress).toHaveLength(1);
    expect(progress[0]!.body).toEqual({ scanned: 1, found: 0, folder: "Home" });
    expect(calls.at(-1)!.path).toBe("/devices/commands/c9/result");
  });

  it("the long poll asks the server whether a command is waiting", async () => {
    const { calls, fetcher } = fakeServer([{ id: "c10", kind: "update_signatures", args: {} }]);
    const agent = new RemoteAgent(host(), fetcher);
    expect(await agent.waitOnce(account)).toBe(true);
    const wait = calls.find((c) => c.path === "/devices/wait")!;
    expect(wait.auth).toBe("Bearer sdv_test");
  });
});

describe("quarantine commands from the account", () => {
  const h = (c: string) => c.repeat(64);
  const history = [
    { path: "/home/u/Downloads/bad.exe", sha256: h("a"), verdict: "malicious" },
    { path: "/home/u/Downloads/odd.js", sha256: h("b"), verdict: "suspicious" },
    { path: "/home/u/Documents/contract.pdf", sha256: h("c"), verdict: "clean" },
    { path: "/home/u/Downloads/bad.exe", sha256: h("a"), verdict: "malicious" },
    { path: "/home/u/Downloads/moved.exe", sha256: h("d"), verdict: "malicious" },
  ];

  it("moves only files this computer flagged, never an ordinary file named by its hash", () => {
    const picked = quarantineCandidates(history, [h("a"), h("b"), h("c"), h("d"), "not-a-hash"], new Set(["/home/u/Downloads/moved.exe"]));
    expect(picked.map((e) => e.path)).toEqual(["/home/u/Downloads/bad.exe", "/home/u/Downloads/odd.js"]);
  });
});

