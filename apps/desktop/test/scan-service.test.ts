import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { IpcError } from "../src/core/protocol";
import { ScanService } from "../src/core/scan-service";
import { createDaemonHost } from "../src/daemon";
import { Quarantine } from "../src/engine/quarantine";
import { EICAR } from "../src/engine/rules";
import type { ScanContext } from "../src/engine/scanner";
import type { ScanResult } from "../src/engine/types";
import { isDirectory, walk } from "../src/engine/walk";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-scan-svc-"));
  folders.push(dir);
  return dir;
}

/** A stand-in engine: files whose content says "BAD" are malicious, "ODD" suspicious. */
async function fakeScan(path: string): Promise<ScanResult> {
  const text = await readFile(path, "utf8");
  const verdict = text.includes("BAD") ? "malicious" : text.includes("ODD") ? "suspicious" : "no_known_threat";
  const findings = verdict === "no_known_threat" ? [] : [{ id: "t", title: verdict === "malicious" ? "Known test threat" : "Odd file", severity: verdict === "malicious" ? "critical" : "medium", detail: "" }];
  return { path, name: path.split("/").pop()!, size: text.length, sha256: "a".repeat(64), verdict, findings, engines: ["signatures"], scannedAt: "2026-11-25T12:00:00.000Z" } as unknown as ScanResult;
}

async function service(dir: string, overrides: Partial<ConstructorParameters<typeof ScanService>[0]> = {}) {
  const watched = join(dir, "Downloads");
  await mkdir(watched, { recursive: true });
  let exclusions: string[] = [];
  const events: { event: string; payload: unknown }[] = [];
  const svc = new ScanService({
    historyFile: join(dir, "history.json"),
    quarantine: new Quarantine(join(dir, "quarantine")),
    scanFile: fakeScan,
    context: () => ({ signatures: {} } as unknown as ScanContext),
    walk,
    isDirectory,
    watchFolders: () => [watched],
    exclusions: () => exclusions,
    saveExclusions: async (next) => {
      exclusions = next;
    },
    emit: (event, payload) => events.push({ event, payload }),
    platform: "linux",
    ...overrides,
  });
  await svc.load();
  return { svc, watched, events };
}

describe.skipIf(process.platform === "win32")("scan service", () => {
  it("quick-scans the watched folders and keeps a summary per file", async () => {
    const dir = await temp();
    const { svc, watched, events } = await service(dir);
    await writeFile(join(watched, "ok.txt"), "fine");
    await writeFile(join(watched, "bad.exe"), "BAD");
    await writeFile(join(watched, "odd.js"), "ODD");
    expect(await svc.quick()).toEqual({ scanned: 3, malicious: 1, suspicious: 1 });
    const status = svc.status();
    expect(status.scanning).toBe(false);
    expect(status.last).toMatchObject({ kind: "quick", scanned: 3, malicious: 1 });
    expect(status.results.find((r) => r.name === "bad.exe")).toMatchObject({ verdict: "malicious", title: "Known test threat", findings: 1, quarantined: null });
    expect(events[0]).toMatchObject({ event: "scan.started", payload: { kind: "quick" } });
    expect(events.at(-1)).toMatchObject({ event: "scan.finished", payload: { scanned: 3 } });
    // Saved, and read back by a new service.
    const again = (await service(dir)).svc;
    expect(again.results()).toHaveLength(3);
  });

  it("a rescan replaces a file's old result instead of listing it twice", async () => {
    const dir = await temp();
    const { svc, watched } = await service(dir);
    const file = join(watched, "a.txt");
    await writeFile(file, "BAD");
    await svc.custom({ paths: [file] });
    await writeFile(file, "fine now");
    await svc.custom({ paths: [file] });
    expect(svc.results().filter((r) => r.path === file).map((r) => r.verdict)).toEqual(["no_known_threat"]);
  });

  it("checks custom paths before scanning", async () => {
    const dir = await temp();
    const { svc } = await service(dir);
    await expect(svc.custom({ paths: [] })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.custom({ paths: ["relative/file"] })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.custom({ paths: [join(dir, "missing")] })).rejects.toMatchObject({ code: "not_found" });
    await expect(svc.custom({ paths: "nope" })).rejects.toBeInstanceOf(IpcError);
  });

  it("refuses a second scan while one runs", async () => {
    const dir = await temp();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { svc, watched } = await service(dir, {
      scanFile: async (path) => {
        await gate;
        return fakeScan(path);
      },
    });
    await writeFile(join(watched, "slow.txt"), "fine");
    const first = svc.quick();
    await new Promise((r) => setTimeout(r, 20));
    expect(svc.status()).toMatchObject({ scanning: true, kind: "quick" });
    await expect(svc.quick()).rejects.toMatchObject({ code: "busy" });
    release();
    await first;
    expect(svc.isScanning()).toBe(false);
  });

  it("skips excluded folders and validates exclusions", async () => {
    const dir = await temp();
    const { svc, watched } = await service(dir);
    const skipped = join(watched, "builds");
    await mkdir(skipped);
    await writeFile(join(skipped, "big.bin"), "BAD");
    await writeFile(join(watched, "keep.txt"), "fine");
    expect((await svc.addExclusion({ path: skipped })).exclusions).toEqual([skipped]);
    expect(await svc.quick()).toMatchObject({ scanned: 1, malicious: 0 });
    await expect(svc.addExclusion({ path: "/" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.addExclusion({ path: "relative" })).rejects.toMatchObject({ code: "bad_params" });
    expect((await svc.removeExclusion({ path: skipped })).exclusions).toEqual([]);
  });

  it("the inspector returns every finding for one scanned file", async () => {
    const dir = await temp();
    const { svc, watched } = await service(dir);
    const file = join(watched, "bad.exe");
    await writeFile(file, "BAD");
    await svc.quick();
    expect(svc.details({ path: file })).toMatchObject({ verdict: "malicious", findings: [{ title: "Known test threat" }], engines: ["signatures"], quarantined: null });
    expect(() => svc.details({ path: join(watched, "never") })).toThrow(/isn't in the scan results/);
  });

  it("quarantines a scanned file, then restores or deletes it", async () => {
    const dir = await temp();
    const { svc, watched } = await service(dir);
    const file = join(watched, "bad.exe");
    await writeFile(file, "BAD");
    await svc.quick();
    // Only files that were scanned: a client can't move arbitrary files by path.
    await expect(svc.quarantineAdd({ path: "/etc/passwd" })).rejects.toMatchObject({ code: "not_found" });
    const item = await svc.quarantineAdd({ path: file });
    expect(item).toMatchObject({ name: "bad.exe", verdict: "malicious", reason: "Known test threat" });
    await expect(stat(file)).rejects.toThrow();
    expect(svc.status().results[0]?.quarantined).toBe(item.id);
    expect((await svc.quarantineList()).map((i) => i.id)).toEqual([item.id]);

    const { path } = await svc.quarantineRestore({ id: item.id });
    expect(path).toBe(file);
    expect(await readFile(file, "utf8")).toBe("BAD");
    expect(svc.status().results[0]?.quarantined).toBeNull();

    const again = await svc.quarantineAdd({ path: file });
    expect(await svc.quarantineDelete({ id: again.id })).toEqual({ deleted: true });
    expect(await svc.quarantineList()).toEqual([]);
    await expect(svc.quarantineRestore({ id: again.id })).rejects.toMatchObject({ code: "not_found" });
  });

  it("says when the deep check isn't available", async () => {
    const dir = await temp();
    const { svc } = await service(dir);
    await expect(svc.deep()).rejects.toMatchObject({ code: "unavailable" });
    const withDeep = (await service(dir, { deepCheck: async () => ({ findings: [{ area: "Startup", item: "x", severity: "high", detail: "d" }], checked: ["Startup"] }) })).svc;
    expect(await withDeep.deep()).toMatchObject({ findings: [{ area: "Startup" }], checked: ["Startup"], checkedAt: expect.any(String) });
  });
});

describe.skipIf(process.platform === "win32")("scan and quarantine over the daemon's handlers", () => {
  it("scans EICAR with the real engine, inspects, quarantines and restores it", { timeout: 30_000 }, async () => {
    const dataDir = await temp();
    const downloads = join(dataDir, "Downloads");
    await mkdir(downloads);
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ watchFolders: [downloads], serverUrl: "http://127.0.0.1:9", cloudLookup: false, useClamav: false }));
    const eicar = join(downloads, "eicar.com");
    await writeFile(eicar, EICAR);
    const events: string[] = [];
    const host = await createDaemonHost(dataDir);
    const h = createHandlers(host, (event) => events.push(event));

    const totals = await h["scan.custom"]!({ paths: [downloads] });
    expect(totals).toMatchObject({ scanned: 1, malicious: 1 });
    expect(events).toContain("home.changed");
    const status = (await h["scan.get"]!(undefined)) as { results: { path: string; verdict: string }[]; engines: { clamav: boolean } };
    expect(status.results[0]).toMatchObject({ path: eicar, verdict: "malicious" });
    expect(status.engines.clamav).toBe(false);
    const details = (await h["scan.details"]!({ path: eicar })) as { findings: unknown[] };
    expect(details.findings.length).toBeGreaterThan(0);

    const item = (await h["quarantine.add"]!({ path: eicar })) as { id: string };
    const list = (await h["quarantine.list"]!(undefined)) as { items: { id: string }[] };
    expect(list.items.map((i) => i.id)).toEqual([item.id]);
    const home = (await h["home.get"]!(undefined)) as { checks: unknown[] };
    expect(home.checks.length).toBeGreaterThan(0);
    expect(await h["quarantine.restore"]!({ id: item.id })).toEqual({ path: eicar });
    expect((await readFile(eicar)).equals(Buffer.from(EICAR))).toBe(true);

    // Home's quick scan goes through the same service and history.
    expect(await h["scan.quick"]!(undefined)).toMatchObject({ scanned: 1, malicious: 1 });
    expect(JSON.parse(await readFile(join(dataDir, "history.json"), "utf8"))).toHaveLength(1);
  });

  it("a host without the service says so", async () => {
    const h = createHandlers({ version: "x", homeInput: async () => { throw new Error("unused"); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {} }, () => {});
    await expect(h["scan.get"]!(undefined)).rejects.toMatchObject({ code: "unavailable" });
    await expect(h["quarantine.list"]!(undefined)).rejects.toMatchObject({ code: "unavailable" });
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const SCAN_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/scan.json");

it("scan replies match the fixture the Rust client decodes", async () => {
  const files: Record<string, string> = { "/home/me/Downloads/invoice.pdf.exe": "BAD", "/home/me/Downloads/notes.txt": "fine", "/home/me/Downloads/setup.js": "ODD" };
  const items: { id: string; originalPath: string; name: string; size: number; sha256: string | null; verdict: "malicious"; reason: string; quarantinedAt: string }[] = [];
  const fakeQuarantine = {
    list: async () => items,
    add: async (path: string, d: { sha256: string | null; reason: string }) => {
      const item = { id: "q-1", originalPath: path, name: path.split("/").pop()!, size: 3, sha256: d.sha256, verdict: "malicious" as const, reason: d.reason, quarantinedAt: "2026-11-25T12:01:00.000Z" };
      items.push(item);
      return item;
    },
    restore: async () => "",
    remove: async () => {},
  } as unknown as Quarantine;
  const svc = new ScanService({
    historyFile: join(await temp(), "history.json"),
    quarantine: fakeQuarantine,
    scanFile: async (path) => ({ ...(await fakeScanText(path, files[path]!)) }),
    context: () => ({ signatures: {}, clamBinary: "/usr/bin/clamscan", nativeScanner: null } as unknown as ScanContext),
    walk: async function* () {
      yield* Object.keys(files);
    },
    isDirectory: async (p) => p === "/home/me/Downloads",
    watchFolders: () => ["/home/me/Downloads"],
    exclusions: () => ["/home/me/Downloads/builds"],
    saveExclusions: async () => {},
    platform: "linux",
    now: () => Date.parse("2026-11-25T12:00:30.000Z"),
  });
  await svc.quick();
  const item = await svc.quarantineAdd({ path: "/home/me/Downloads/invoice.pdf.exe" });
  const fixture = {
    status: svc.status(),
    details: svc.details({ path: "/home/me/Downloads/setup.js" }),
    quarantine: { items: await svc.quarantineList() },
    added: item,
  };
  if (process.env.UPDATE_FIXTURES) await writeFile(SCAN_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(SCAN_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});

async function fakeScanText(path: string, text: string): Promise<ScanResult> {
  const verdict = text.includes("BAD") ? "malicious" : text.includes("ODD") ? "suspicious" : "no_known_threat";
  const findings =
    verdict === "no_known_threat"
      ? []
      : [{ rule: verdict === "malicious" ? "sig.test" : "heur.script", title: verdict === "malicious" ? "Known test threat" : "Script downloads and runs a file", severity: verdict === "malicious" ? "critical" : "medium", detail: "Matched in the first 4 KB." }];
  return { path, name: path.split("/").pop()!, size: text.length, sha256: "b".repeat(64), verdict, findings, engines: ["signatures", "heuristics"], scannedAt: "2026-11-25T12:00:00.000Z" } as unknown as ScanResult;
}
