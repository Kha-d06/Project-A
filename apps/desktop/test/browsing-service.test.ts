import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { type BrowsingDeps, BrowsingService } from "../src/core/browsing-service";
import type { HistoryReport, ThreatList } from "../src/engine/history";
import type { ExtensionInfo } from "../src/engine/tools";

const account = { deviceId: "d1", token: "t", email: "a@example.com", server: "https://q.example" };
const report = (list: ThreatList, days: number): HistoryReport => ({
  checkedAt: "2026-11-25T12:00:00.000Z",
  days,
  browsers: [
    { browser: "Firefox", profile: "default-release", visits: 1200, error: null },
    { browser: "Chrome", profile: "Default", visits: 0, error: "The history file is locked while Chrome is open" },
  ],
  matches: list.hosts.includes("bad.example") ? [{ browser: "Firefox", profile: "default-release", url: "https://bad.example/login", host: "bad.example", visitedAt: "2026-11-24T20:00:00.000Z", reason: "domain" }] : [],
});
const extension: ExtensionInfo = { browser: "Chrome", profile: "Default", id: "a".repeat(32), name: "Coupon Finder", version: "3.2", fromStore: false, enabled: true, risk: "high", reasons: ["can read and change every site you visit", "wasn't installed from the store"] };

function fakes(overrides: Partial<BrowsingDeps> = {}) {
  const calls: string[] = [];
  const events: unknown[] = [];
  const deps: BrowsingDeps = {
    account: async () => account,
    blocklist: async () => ({ hosts: ["bad.example"], urls: [] }),
    checkHistory: async (list, days) => {
      calls.push(`history ${days}`);
      return report(list, days);
    },
    extensions: async () => [extension],
    emit: (_e, p) => events.push(p),
    now: () => Date.parse("2026-11-25T12:00:00Z"),
    ...overrides,
  };
  return { svc: new BrowsingService(deps), calls, events };
}

describe("browsing service", () => {
  it("compares history with the server's list on this computer, and alerts on a match", async () => {
    const { svc, calls, events } = fakes();
    const status = await svc.checkHistory({ days: 14 });
    expect(calls).toEqual(["history 14"]);
    expect(status.history?.matches[0]).toMatchObject({ host: "bad.example", reason: "domain" });
    expect(status.history?.browsers[1]?.error).toMatch(/locked/);
    expect(events).toEqual([{ kind: "history", matches: 1 }]);
    expect((await svc.clearHistory()).history).toBeNull();
  });

  it("needs a linked account and a sensible number of days", async () => {
    await expect(fakes({ account: async () => null }).svc.checkHistory({})).rejects.toMatchObject({ code: "not_linked" });
    const { svc } = fakes();
    for (const days of [0, 91, 1.5, "30"]) await expect(svc.checkHistory({ days })).rejects.toMatchObject({ code: "bad_params" });
    expect((await svc.checkHistory(undefined)).history?.days).toBe(30);
  });

  it("a list that can't be downloaded is an error, not an all-clear", async () => {
    const { svc } = fakes({ blocklist: async () => Promise.reject(new Error("the server answered 503")) });
    await expect(svc.checkHistory({ days: 7 })).rejects.toMatchObject({ code: "failed", message: expect.stringContaining("503") });
    expect((await svc.status()).history).toBeNull();
  });

  it("lists extensions with their risk; one check at a time", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const { svc } = fakes({
      extensions: async () => {
        await gate;
        return [extension];
      },
    });
    const first = svc.checkExtensions();
    await expect(svc.checkHistory({ days: 7 })).rejects.toMatchObject({ code: "busy" });
    release();
    const status = await first;
    expect(status.extensions).toEqual({ items: [extension], checkedAt: "2026-11-25T12:00:00.000Z" });
    expect(status.checking).toBe(false);
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const BROWSING_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/browsing.json");

it("browsing replies match the fixture the Rust client decodes", async () => {
  const { svc } = fakes();
  await svc.checkHistory({ days: 30 });
  const fixture = { status: await svc.checkExtensions() };
  if (process.env.UPDATE_FIXTURES) await writeFile(BROWSING_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(BROWSING_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});
