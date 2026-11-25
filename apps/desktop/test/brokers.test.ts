import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { BrokerService, CATALOG, type Catalog, fillTemplate, validateCatalog } from "../src/core/broker-service";
import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";

const DAY = 24 * 60 * 60 * 1000;

async function service(now: { t: number }, copied: string[] = []) {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-brokers-"));
  const s = new BrokerService(join(dir, "brokers.json"), CATALOG, () => now.t, async (text) => void copied.push(text));
  await s.load();
  return { s, file: join(dir, "brokers.json") };
}

describe("the bundled broker catalog", () => {
  it("is well formed: https opt-out pages on each broker's own site, steps, templates", () => {
    expect(validateCatalog(CATALOG)).toEqual([]);
    expect(CATALOG.brokers.length).toBeGreaterThanOrEqual(10);
    expect(CATALOG.recheckDays).toBe(90);
  });

  it("catches a bad entry", () => {
    const bad: Catalog = {
      ...CATALOG,
      brokers: [{ ...CATALOG.brokers[0]!, optOutUrl: "http://evil.example/optout" }, { ...CATALOG.brokers[0]!, template: "nope", steps: [] }],
    };
    const problems = validateCatalog(bad);
    expect(problems.some((p) => p.includes("https on"))).toBe(true);
    expect(problems.some((p) => p.includes("duplicate"))).toBe(true);
    expect(problems.some((p) => p.includes("unknown template"))).toBe(true);
    expect(problems.some((p) => p.includes("no steps"))).toBe(true);
  });
});

describe("progress, kept on this computer", () => {
  it("records requests and removals, and asks for a re-check after 90 days", async () => {
    const now = { t: Date.parse("2026-11-25T10:00:00Z") };
    const { s, file } = await service(now);
    expect(s.status().brokers.every((b) => b.state === "todo")).toBe(true);
    const requested = await s.mark({ id: "spokeo", state: "requested" });
    const spokeo = requested.brokers.find((b) => b.id === "spokeo")!;
    expect(spokeo.expectedBy).toBe(new Date(now.t + 3 * DAY).toISOString());
    await s.mark({ id: "acxiom", state: "removed" });
    await s.mark({ id: "radaris", state: "not_listed" });
    expect(s.status()).toMatchObject({ done: 3, recheckDue: 0 });

    now.t += 91 * DAY;
    const later = s.status();
    // Requests and removals come back; "not listed" doesn't need a reminder.
    expect(later.recheckDue).toBe(2);
    expect(later.brokers.find((b) => b.id === "radaris")!.recheckDue).toBe(false);
    // Checking again restarts the clock.
    await s.mark({ id: "spokeo", state: "removed" });
    expect(s.status().recheckDue).toBe(1);

    // Saved to disk without names or emails, and loaded back.
    const saved = JSON.parse(await readFile(file, "utf8")) as { catalogVersion: string; progress: Record<string, unknown> };
    expect(saved.catalogVersion).toBe(CATALOG.version);
    expect(Object.keys(saved.progress).sort()).toEqual(["acxiom", "radaris", "spokeo"]);
    const reloaded = new BrokerService(file, CATALOG, () => now.t);
    await reloaded.load();
    expect(reloaded.status().recheckDue).toBe(1);
    await s.mark({ id: "acxiom", state: "todo" });
    expect(s.status().brokers.find((b) => b.id === "acxiom")!.state).toBe("todo");
  });

  it("refuses unknown brokers and states", async () => {
    const { s } = await service({ t: 0 });
    await expect(s.mark({ id: "nobody", state: "removed" })).rejects.toMatchObject({ code: "not_found" });
    await expect(s.mark({ id: "spokeo", state: "deleted" })).rejects.toMatchObject({ code: "bad_params" });
  });
});

describe("request letters", () => {
  it("fills in the company, name and email, and can copy the letter", async () => {
    const copied: string[] = [];
    const { s } = await service({ t: 0 }, copied);
    const letter = await s.template({ id: "acxiom", name: "Amira K", email: "amira@example.com", copy: true });
    expect(letter.subject).toContain("Article 17");
    expect(letter.body).toContain("Hello Acxiom,");
    expect(letter.body).toContain("Name: Amira K\nEmail: amira@example.com");
    expect(letter.body).not.toMatch(/\{(name|email|broker)\}/);
    expect(letter.copied).toBe(true);
    expect(copied[0]).toContain(letter.subject);
    // Brokers without a legal template get the general one.
    expect((await s.template({ id: "spokeo", name: "A", email: "a@b.co" })).subject).toBe("Request to erase my personal data");
    await expect(s.template({ id: "acxiom", name: "", email: "a@b.co" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(s.template({ id: "acxiom", name: "A", email: "nope" })).rejects.toMatchObject({ code: "bad_params" });
    expect(fillTemplate({ subject: "{broker}", body: "{name} {email} {other}" }, { broker: "X", name: "N", email: "E" })).toEqual({ subject: "X", body: "N E {other}" });
  });
});

describe("over IPC and on Home", () => {
  it("serves the checklist and reminds on Home when a re-check is due", async () => {
    const now = { t: Date.parse("2026-11-25T10:00:00Z") };
    const { s } = await service(now);
    const emitted: string[] = [];
    const homeInput = async () => ({
      now: new Date(now.t), platform: "linux" as const, watchEnabled: true, onAccessScan: false, ransomwareWatch: true, networkWatch: true, cloudLookup: true,
      signatures: { count: 1, updatedAt: new Date(now.t).toISOString(), error: null }, lastScanAt: new Date(now.t).toISOString(), lastNetworkScanAt: new Date(now.t).toISOString(),
      lastBackupAt: new Date(now.t).toISOString(), lastBackupError: null, backupConfigured: true, quarantineCount: 0, recentThreats: 0, ransomwareAlertAt: null, updateAvailable: null, silentUntil: null,
      brokersRecheckDue: s.recheckDueCount(),
    });
    const handlers = createHandlers({ version: "t", brokers: s, homeInput, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} }, (e) => emitted.push(e));
    await handlers["brokers.mark"]!({ id: "spokeo", state: "requested" });
    expect(emitted).toContain("home.changed");
    expect(buildHome(await homeInput()).actions.some((a) => a.id === "recheck_brokers")).toBe(false);
    now.t += 90 * DAY;
    const home = buildHome(await homeInput());
    expect(home.actions.find((a) => a.id === "recheck_brokers")).toEqual({ id: "recheck_brokers", priority: 3, command: { method: "view.open", params: { view: "brokers" } } });
    expect(((await handlers["brokers.get"]!(undefined)) as { recheckDue: number }).recheckDue).toBe(1);
  });
});
