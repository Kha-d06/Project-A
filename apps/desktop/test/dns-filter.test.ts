/** Ad and tracker lists for Safe DNS through qalaa-dns (adblock-rust), Wave 4.D. */
import { existsSync } from "node:fs";
import { chmod, mkdtemp, readFile, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { SafeDnsService } from "../src/core/safe-dns-service";
import { DnsFilterProcess, FILTER_LISTS, looksLikeFilterList, refreshLists } from "../src/engine/dns-filter";
import { TYPE, buildQuery, parseQuery, responseCode } from "../src/engine/dns-wire";
import { SafeDnsProxy } from "../src/engine/safe-dns";

const BUILT = resolve(__dirname, "../../desktop-native/target/debug/qalaa-dns");

function answerWithCname(query: Uint8Array, target: string): Uint8Array {
  const q = parseQuery(query)!;
  const parts: number[] = [...query.subarray(0, q.end)];
  parts[2] = 0x81;
  parts[3] = 0x80;
  parts[7] = 1;
  const name = [...target.split(".").flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0];
  parts.push(0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, name.length >> 8, name.length & 255, ...name);
  return new Uint8Array(parts);
}

describe("filter lists", () => {
  it("recognises Adblock Plus and hosts lists, not web pages", () => {
    expect(looksLikeFilterList("[Adblock Plus 2.0]\n! Title: EasyList\n||ads.example^")).toBe(true);
    expect(looksLikeFilterList("0.0.0.0 tracker.example\n")).toBe(true);
    expect(looksLikeFilterList("<!DOCTYPE html><html>captive portal</html>")).toBe(false);
  });

  it("downloads stale lists and keeps the old copy when a download is wrong", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-lists-"));
    const now = Date.now();
    let served = "! Title: EasyList\n||ads.example^\n";
    const results = await refreshLists(dir, async () => served, now);
    expect(results.every((r) => r.updated)).toBe(true);
    // Fresh lists are left alone.
    expect((await refreshLists(dir, async () => served, now)).every((r) => !r.updated)).toBe(true);
    // A captive portal page five days later doesn't replace a good list.
    const old = new Date(now - 5 * 24 * 3600 * 1000);
    for (const l of FILTER_LISTS) await utimes(join(dir, `${l.id}.txt`), old, old);
    served = "<html>log in to the Wi-Fi</html>";
    const later = await refreshLists(dir, async () => served, now);
    expect(later.every((r) => r.error?.includes("isn't a filter list"))).toBe(true);
    expect(await readFile(join(dir, "easylist.txt"), "utf8")).toContain("||ads.example^");
  });

  it("names each list's licence", () => {
    for (const l of FILTER_LISTS) expect(l.licence).toMatch(/GPL|CC/);
  });
});

describe("the qalaa-dns helper", () => {
  it.runIf(existsSync(BUILT))("answers from adblock-rust and caches", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-dnsf-"));
    await writeFile(join(dir, "l.txt"), "||ads.example^\n||t.example^$third-party\n@@||ok.ads.example^\n");
    const f = new DnsFilterProcess(BUILT, [join(dir, "l.txt")]);
    await f.start();
    expect(f.rules).toBe(3);
    expect(await f.check("x.ads.example")).toMatchObject({ blocked: true, rule: "||ads.example^" });
    expect((await f.check("ok.ads.example"))?.blocked).toBe(false);
    expect((await f.check("t.example"))?.blocked).toBe(false);
    expect((await f.check("X.ADS.EXAMPLE."))?.blocked).toBe(true);
    f.stop();
    expect(await f.check("new.example")).toBeNull();
  });

  it.runIf(process.platform !== "win32")("never makes DNS wait on a stuck helper", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-dnsf-stuck-"));
    const stuck = join(dir, "qalaa-dns");
    await writeFile(stuck, '#!/bin/sh\necho \'{"ready":true,"rules":1}\'\nsleep 30\n');
    await chmod(stuck, 0o755);
    const f = new DnsFilterProcess(stuck, []);
    await f.start();
    const started = Date.now();
    expect(await f.check("ads.example")).toBeNull();
    expect(Date.now() - started).toBeLessThan(1_000);
    f.stop();
  });
});

describe("Safe DNS with the lists", () => {
  const proxy = (filter: (n: string) => Promise<{ blocked: boolean; rule: string | null } | null>, cname?: string) =>
    new SafeDnsProxy({
      blocklist: () => new Set(),
      upstream: "https://doh.test/dns-query",
      fallback: () => [],
      doh: async (_u, q) => (cname ? answerWithCname(q, cname) : answerWithCname(q, "edge.cdn.example")),
      filter,
    });

  it("refuses listed names and trackers hidden behind a CNAME, and allows when the filter has no opinion", async () => {
    const lists = async (n: string) => ({ blocked: n.endsWith("ads.example") || n === "metrics.tracker.example", rule: null });
    const p = proxy(lists);
    expect(responseCode((await p.resolve(buildQuery(7, "banner.ads.example", TYPE.A)))!)).toBe(3);
    const cloaked = proxy(lists, "metrics.tracker.example");
    expect(responseCode((await cloaked.resolve(buildQuery(7, "stats.news.example", TYPE.A)))!)).toBe(3);
    expect(cloaked.stats.listBlocked).toBe(1);
    expect(responseCode((await proxy(async () => null).resolve(buildQuery(7, "news.example", TYPE.A)))!)).toBe(0);
    expect(responseCode((await proxy(async () => { throw new Error("helper crashed"); }).resolve(buildQuery(7, "news.example", TYPE.A)))!)).toBe(0);
  });

  it("never filters the operating systems' captive-portal checks", async () => {
    const p = proxy(async () => ({ blocked: true, rule: "||*^" }));
    expect(responseCode((await p.resolve(buildQuery(7, "captive.apple.com", TYPE.A)))!)).not.toBe(3);
  });
});

describe("Safe DNS service switch", () => {
  it("says plainly when the helper isn't installed or the lists can't be fetched", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-sds-"));
    const none = new SafeDnsService(join(dir, "s.json"), () => "https://server.test", { platform: "linux", available: async () => true, filterBinary: null, listsDir: join(dir, "lists") });
    await none.load();
    const s = await none.setAdBlocking(true);
    expect(s.adBlocking).toMatchObject({ on: true, available: false, running: false });
    expect(s.adBlocking.note).toMatch(/isn't installed/);

    const offline = new SafeDnsService(join(dir, "s2.json"), () => "https://server.test", {
      platform: "linux", available: async () => true, filterBinary: "/opt/qalaa-dns", listsDir: join(dir, "lists2"),
      refreshLists: async () => [{ id: "easylist", updated: false, error: "offline" }],
    });
    await offline.load();
    expect((await offline.setAdBlocking(true)).adBlocking.note).toMatch(/couldn't be downloaded \(offline\)/);
    expect((await offline.setAdBlocking(false)).adBlocking.on).toBe(false);
    expect(JSON.parse(await readFile(join(dir, "s2.json"), "utf8")).adBlocking).toBe(false);
  });
});
