import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it, vi } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { type ProtectionDeps, type ProtectionSettings, ProtectionService } from "../src/core/protection-service";
import { createDaemonHost } from "../src/daemon";
import { EICAR } from "../src/engine/rules";
import type { ScanResult } from "../src/engine/types";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});

const clean = (path: string) => ({ path, name: path, size: 1, sha256: null, verdict: "no_known_threat", findings: [], engines: [], scannedAt: "2026-11-25T12:00:00Z" }) as unknown as ScanResult;

type Hooks = Parameters<ProtectionDeps["onAccess"]["startResponder"]>[0];

function fakes(overrides: Partial<ProtectionDeps> = {}, start: Partial<ProtectionSettings> = {}) {
  let settings: ProtectionSettings = { watchEnabled: true, watchFolders: ["/home/me/Downloads"], ransomwareWatch: true, ransomwareDecoys: true, protectedFolders: ["/home/me/Documents"], onAccessScan: false, ...start };
  const calls: string[] = [];
  const events: { event: string; payload: unknown }[] = [];
  let hooks: Hooks | null = null;
  let decoyStore: Record<string, string> = {};
  const deps: ProtectionDeps = {
    platform: "linux",
    settings: () => settings,
    saveSettings: async (changes) => {
      settings = { ...settings, ...changes };
      calls.push(`save ${JSON.stringify(changes)}`);
    },
    scanAutomatic: async (path) => calls.push(`auto ${path}`),
    scanFile: async (path) => clean(path),
    isExcluded: (path) => path.includes("/excluded/"),
    emit: (event, payload) => events.push({ event, payload }),
    folderWatcher: { set: (f) => calls.push(`watch ${f.join(",")}`) },
    ransomwareMonitor: { set: (f) => calls.push(`ransomware ${f.join(",")}`), setDecoys: (r) => calls.push(`decoys ${Object.keys(r).length}`) },
    decoys: {
      load: async () => decoyStore,
      save: async (r) => {
        decoyStore = r;
      },
      plant: async (f) => Object.fromEntries(f.map((x) => [`${x}/.qalaa-decoy.docx`, "sha"])),
      tampered: async () => [],
      remove: async (p) => {
        calls.push(`unlink ${p}`);
      },
    },
    onAccess: {
      supported: true,
      status: async () => ({ state: settings.onAccessScan ? "active" : "absent", manageable: true }),
      enable: async () => {
        calls.push("pkexec enable");
      },
      disable: async () => {
        calls.push("pkexec disable");
      },
      startResponder: async (h) => {
        hooks = h;
        calls.push("responder start");
        return { stop: async () => void calls.push("responder stop") };
      },
      burst: { feed: (e) => (e.path.endsWith(".locked") ? { reason: "many files rewritten", files: 40 } : null), clear: (pid) => calls.push(`clear ${pid}`) },
      signal: async (pid, action) => {
        calls.push(`signal ${action} ${pid}`);
      },
    },
    cfa: { status: async () => ({ supported: true, state: "off", folders: [], allowedApps: [] }), apply: async (a, p) => void calls.push(`cfa ${a} ${p ?? ""}`) },
    terminal: {
      status: async () => ({ command: "/home/me/.local/bin/qalaa", shells: [{ shell: "bash", rc: "/home/me/.bashrc", enabled: false }] }),
      enable: async () => ({ changed: ["/home/me/.bashrc"], setup: { command: "q", shells: [] } }),
      disable: async () => ({ changed: [], setup: { command: "q", shells: [] } }),
    },
    acceptChanged: async (files) => void calls.push(`accept ${files.join(",")}`),
    wifi: async () => ({ ssid: "Cafe", security: "", risk: "open" }),
    updates: async () => ({ updates: [{ name: "openssl", current: "3.0.1", available: "3.0.2" }], source: "apt" }),
    now: () => Date.parse("2026-11-25T12:00:00Z"),
    ...overrides,
  };
  return { svc: new ProtectionService(deps), calls, events, hooks: () => hooks!, settings: () => settings };
}

describe("protection service", () => {
  it("starts the watchers and plants decoys in the protected folders", async () => {
    const { svc, calls } = fakes();
    await svc.start();
    expect(calls).toEqual(["watch /home/me/Downloads", "ransomware /home/me/Documents", "decoys 0", "decoys 1"]);
    expect((await svc.status()).ransomware).toMatchObject({ on: true, decoyCount: 1, folders: ["/home/me/Documents"], halted: [] });
  });

  it("reports decoys changed while the service was stopped", async () => {
    const { svc, events } = fakes({ decoys: { load: async () => ({ "/d/x": "s" }), save: async () => {}, plant: async () => ({}), tampered: async () => [{ path: "/d/x", state: "missing" }], remove: async () => {} } });
    await svc.start();
    expect(events[0]).toMatchObject({ event: "alert", payload: { kind: "ransomware" } });
    expect((await svc.status()).ransomware.lastAlert?.reasons[0]).toMatch(/while Qalaa was not running/);
  });

  it("toggles follow the settings: off stops watching and removes decoys", async () => {
    const { svc, calls } = fakes();
    await svc.start();
    calls.length = 0;
    await svc.setRealtime({ on: false });
    expect(calls).toContain("watch ");
    await svc.setRansomware({ on: false });
    expect(calls).toContain("ransomware ");
    expect(calls).toContain("unlink /home/me/Documents/.qalaa-decoy.docx");
    await expect(svc.setRealtime({ on: "yes" })).rejects.toMatchObject({ code: "bad_params" });
  });

  it("scans new files except excluded ones", async () => {
    const { svc, calls } = fakes();
    svc.onNewFile("/home/me/Downloads/setup.exe");
    svc.onNewFile("/home/me/excluded/big.iso");
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toEqual(["auto /home/me/Downloads/setup.exe"]);
  });

  it("protected folders must be full paths", async () => {
    const { svc, settings } = fakes();
    await svc.addFolder({ path: "/home/me/Pictures" });
    expect(settings().protectedFolders).toEqual(["/home/me/Documents", "/home/me/Pictures"]);
    await expect(svc.addFolder({ path: "Pictures" })).rejects.toMatchObject({ code: "bad_params" });
    await svc.removeFolder({ path: "/home/me/Documents" });
    expect(settings().protectedFolders).toEqual(["/home/me/Pictures"]);
  });

  it("on-access: helper install via pkexec, responder, and a failed install leaves it off", async () => {
    const { svc, calls, settings } = fakes();
    const on = await svc.setOnAccess({ on: true });
    expect(calls).toEqual(["responder start", "pkexec enable", 'save {"onAccessScan":true}']);
    expect(on.onAccess).toMatchObject({ on: true, state: "active", responder: true });
    await svc.setOnAccess({ on: false });
    expect(calls.slice(-3)).toEqual(["pkexec disable", "responder stop", 'save {"onAccessScan":false}']);

    const refused = fakes({}, {});
    refused.svc["deps"].onAccess.enable = async () => {
      throw new Error("Request dismissed");
    };
    await expect(refused.svc.setOnAccess({ on: true })).rejects.toMatchObject({ code: "failed", message: "Request dismissed" });
    expect(refused.settings().onAccessScan).toBe(false);
    expect(refused.calls).toContain("responder stop");
    expect(settings().onAccessScan).toBe(false);

    const windows = fakes({ onAccess: { ...fakes()["svc"]["deps"].onAccess, supported: false } });
    await expect(windows.svc.setOnAccess({ on: true })).rejects.toMatchObject({ code: "unavailable" });
  });

  it("freezes a ransomware-like process only in protected folders, then resumes or removes it", async () => {
    const { svc, calls, events, hooks } = fakes({}, { onAccessScan: true });
    await svc.start();
    expect(hooks().feed(4242, "/home/me/Documents/a.locked")).toMatchObject({ reason: "many files rewritten" });
    expect(hooks().feed(4242, "/tmp/a.locked")).toBeNull();
    hooks().onHalt(4242, "many files rewritten", 40);
    expect(events.at(-1)).toMatchObject({ event: "alert", payload: { kind: "ransomware", halted: 4242 } });
    expect((await svc.status()).ransomware.halted).toEqual([{ pid: 4242, reason: "many files rewritten", files: 40, at: "2026-11-25T12:00:00.000Z" }]);
    await expect(svc.resolveHalted({ pid: 1, action: "kill" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.resolveHalted({ pid: 4242, action: "explode" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.resolveHalted({ pid: 999, action: "kill" })).rejects.toMatchObject({ code: "not_found" });
    await svc.resolveHalted({ pid: 4242, action: "kill" });
    expect(calls).toContain("signal kill 4242");
    expect(calls).toContain("clear 4242");
    expect((await svc.status()).ransomware.halted).toEqual([]);
    // A blocked open is recorded like any automatic scan.
    hooks().onBlocked("/home/me/Downloads/x.exe", clean("/home/me/Downloads/x.exe"));
    expect(calls).toContain("auto /home/me/Downloads/x.exe");
  });

  it("ransomware watch off: the on-access feed no longer freezes anything", async () => {
    const { svc, hooks } = fakes({}, { onAccessScan: true, ransomwareWatch: false });
    await svc.start();
    expect(hooks().feed(7, "/home/me/Documents/a.locked")).toBeNull();
  });

  it("Controlled Folder Access is Windows only, with full paths", async () => {
    const linux = fakes();
    await expect(linux.svc.cfaApply({ action: "enable" })).rejects.toMatchObject({ code: "unavailable" });
    expect((await linux.svc.status()).cfa).toBeNull();
    const win = fakes({ platform: "win32" });
    await win.svc.cfaApply({ action: "add-folder", path: "D:\\Work" });
    expect(win.calls).toContain("cfa add-folder D:\\Work");
    await expect(win.svc.cfaApply({ action: "add-folder", path: "Work" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(win.svc.cfaApply({ action: "format-c" })).rejects.toMatchObject({ code: "bad_params" });
    expect((await win.svc.status()).cfa).toMatchObject({ supported: true, state: "off" });
  });

  it("terminal protection: Qalaa's own shell-profile edit is accepted by integrity checks", async () => {
    const { svc, calls } = fakes();
    const status = await svc.setTerminal({ on: true });
    expect(calls).toContain("accept /home/me/.bashrc");
    expect(status.terminal).toMatchObject({ supported: true, command: "/home/me/.local/bin/qalaa" });
    const win = fakes({ platform: "win32" });
    await expect(win.svc.setTerminal({ on: true })).rejects.toMatchObject({ code: "unavailable" });
    expect((await win.svc.status()).terminal.supported).toBe(false);
  });

  it("Wi-Fi and updates: each failure is reported as unknown, not as fine", async () => {
    const { svc } = fakes();
    expect(await svc.system()).toMatchObject({ wifi: { ssid: "Cafe", risk: "open" }, updates: { count: 1, source: "apt" } });
    const broken = fakes({ wifi: async () => Promise.reject(new Error("no nmcli")), updates: async () => null });
    expect(await broken.svc.system()).toMatchObject({ wifi: null, updates: null });
  });
});

describe.skipIf(process.platform === "win32")("protection over the daemon", () => {
  it("a new download is scanned by the real watcher and engine, quarantined and announced", { timeout: 30_000 }, async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "qalaa-protect-"));
    folders.push(dataDir);
    const downloads = join(dataDir, "Downloads");
    await mkdir(downloads);
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ watchFolders: [downloads], protectedFolders: [], serverUrl: "http://127.0.0.1:9", cloudLookup: false, useClamav: false, onAccessScan: false }));
    const events: { event: string; payload: unknown }[] = [];
    const host = await createDaemonHost(dataDir, (event, payload) => events.push({ event, payload }));
    const h = createHandlers(host, (event, payload) => events.push({ event, payload }));
    await host.protection.start();
    try {
      const status = (await h["protection.get"]!(undefined)) as { realtime: { on: boolean }; onAccess: { supported: boolean } };
      expect(status.realtime.on).toBe(true);
      expect(status.onAccess.supported).toBe(process.platform === "linux");
      const dropped = join(downloads, "invoice.com");
      await writeFile(dropped, EICAR);
      await vi.waitFor(() => expect(events.some((e) => e.event === "threat.blocked")).toBe(true), { timeout: 15_000, interval: 100 });
      await expect(stat(dropped)).rejects.toThrow(); // moved into the encrypted quarantine
      const list = (await h["quarantine.list"]!(undefined)) as { items: { name: string }[] };
      expect(list.items.map((i) => i.name)).toEqual(["invoice.com"]);

      // Real-time off from Home: a new file is no longer picked up.
      await h["settings.set"]!({ watchEnabled: false });
      expect(((await h["protection.get"]!(undefined)) as { realtime: { on: boolean } }).realtime.on).toBe(false);
      expect(JSON.parse(await readFile(join(dataDir, "settings.json"), "utf8")).watchEnabled).toBe(false);
    } finally {
      await host.protection.stop();
    }
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const PROTECTION_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/protection.json");

it("protection replies match the fixture the Rust client decodes", async () => {
  const linux = fakes({}, { onAccessScan: true });
  await linux.svc.start();
  linux.hooks().onHalt(4242, "40 files rewritten in 10 seconds", 40);
  linux.svc.ransomwareAlert({ reasons: ["a hidden decoy file that nothing should touch was changed (.qalaa-decoy.docx in Documents)"], examples: ["/home/me/Documents/.qalaa-decoy.docx"] });
  const windows = fakes({ platform: "win32", cfa: { status: async () => ({ supported: true, state: "audit", folders: ["D:\\Work"], allowedApps: ["C:\\Tools\\sync.exe"] }), apply: async () => {} } });
  const fixture = { linux: await linux.svc.status(), windows: await windows.svc.status(), system: await linux.svc.system() };
  if (process.env.UPDATE_FIXTURES) await writeFile(PROTECTION_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(PROTECTION_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});
