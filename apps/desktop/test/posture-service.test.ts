import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { type PostureDeps, PostureService } from "../src/core/posture-service";
import { createDaemonHost } from "../src/daemon";
import type { IntegrityStore } from "../src/engine/integrity";
import { scoreChecks } from "../src/engine/posture";
import type { StartupItem } from "../src/engine/security";
import type { DisabledStartup } from "../src/engine/tools";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-posture-"));
  folders.push(dir);
  return dir;
}

const item = (id: string, warnings: string[] = []): StartupItem => ({ id, name: id, command: `/usr/bin/${id}`, location: "systemd user services", program: `/usr/bin/${id}`, source: `${id}.service`, warnings });

function fakes(overrides: Partial<PostureDeps> = {}) {
  let known: string[] = [];
  let disabled: DisabledStartup[] = [];
  let startup = [item("syncthing"), item("updater", ["Downloads and runs a script at every start"])];
  const integrityState: IntegrityStore = { paths: ["/etc/hosts"], baseline: {}, changes: [], lastCheck: null };
  const calls: string[] = [];
  const deps: PostureDeps = {
    platform: "linux",
    posture: async (facts) => {
      calls.push(`posture ${JSON.stringify(facts)}`);
      const checks = [
        { id: "firewall", title: "Firewall", status: facts.firewall === "on" ? "pass" : "fail", detail: "", fix: null, weight: 2 },
        { id: "tpm", title: "TPM 2.0", status: "pass", detail: "", fix: null, weight: 2 },
        { id: "secure_boot", title: "Secure Boot", status: "unknown", detail: "Couldn't read the firmware setting", fix: null, weight: 2 },
        { id: "encryption", title: "Disk encryption", status: facts.encryption === "on" ? "pass" : "fail", detail: "LUKS", fix: null, weight: 3 },
      ] as unknown as Awaited<ReturnType<PostureDeps["posture"]>>["checks"];
      return { score: scoreChecks(checks), checks, checkedAt: "2026-11-25T12:00:00.000Z" };
    },
    firewall: async () => ({ state: "on", detail: "ufw active", source: "ufw" }),
    encryption: async () => ({ state: "on", detail: "LUKS2 on /", source: "lsblk" }),
    pendingUpdates: async () => 3,
    ports: async () => [{ port: 23, address: "0.0.0.0", process: "telnetd", pid: 9, exposed: true, risk: "Telnet sends passwords in the clear" }] as never,
    startup: async () => startup,
    canSwitchOff: (s) => s.location === "systemd user services",
    switchOff: async (s) => {
      calls.push(`off ${s.id}`);
      startup = startup.filter((x) => x.id !== s.id);
      return { id: s.id, name: s.name, command: s.command, location: s.location, at: "2026-11-25T12:00:00Z", method: "systemd-user", data: { unit: s.source! } } as DisabledStartup;
    },
    switchOn: async (e) => {
      calls.push(`on ${e.id}`);
      startup = [...startup, item(e.id)];
    },
    knownStartup: () => known,
    saveKnownStartup: async (ids) => {
      known = ids;
    },
    loadDisabled: async () => disabled,
    saveDisabled: async (e) => {
      disabled = e;
    },
    integrity: {
      state: integrityState,
      check: async () => [],
      accept: async (p) => {
        integrityState.changes = integrityState.changes.filter((c) => c.path !== p);
        return integrityState;
      },
      setPaths: async (paths) => {
        integrityState.paths = paths;
        return integrityState;
      },
      rebaseline: async () => integrityState,
    },
    newKeyboards: () => 1,
    ...overrides,
  };
  return { svc: new PostureService(deps), calls, addStartup: (s: StartupItem) => (startup = [...startup, s]), integrityState };
}

describe("posture service", () => {
  it("scores the checks, and unknown checks don't count either way", async () => {
    const { svc, calls } = fakes();
    const status = await svc.check();
    expect(calls[0]).toBe('posture {"firewall":"on","encryption":"on","pendingUpdates":3,"riskyPorts":1,"suspiciousStartup":1}');
    expect(status.posture?.score).toBe(100); // 3 pass, 1 unknown
    expect(status.firewall?.state).toBe("on");
    expect(status.encryption?.detail).toBe("LUKS2 on /");
    expect(status.usb.newKeyboards).toBe(1);
  });

  it("the first check sets the startup baseline; later ones mark what's new", async () => {
    const { svc, addStartup } = fakes();
    const first = await svc.check();
    expect(first.startupBaselineSet).toBe(true);
    expect(first.startup.every((s) => !s.isNew)).toBe(true);
    addStartup(item("miner", ["Starts a program from a temporary or Downloads folder"]));
    const second = await svc.check();
    expect(second.startup.find((s) => s.id === "miner")?.isNew).toBe(true);
    const acked = await svc.acknowledgeStartup();
    expect(acked.startup.some((s) => s.isNew)).toBe(false);
  });

  it("switches a startup entry off and back on, only where no administrator is needed", async () => {
    const { svc, calls, addStartup } = fakes({ canSwitchOff: (s) => s.id !== "systemwide" });
    addStartup(item("systemwide"));
    await svc.check();
    const off = await svc.startupOff({ id: "updater" });
    expect(off.disabledStartup.map((d) => d.id)).toEqual(["updater"]);
    expect(off.startup.some((s) => s.id === "updater")).toBe(false);
    await expect(svc.startupOff({ id: "systemwide" })).rejects.toMatchObject({ code: "not_allowed" });
    await expect(svc.startupOff({ id: "gone" })).rejects.toMatchObject({ code: "not_found" });
    const on = await svc.startupOn({ id: "updater" });
    expect(on.disabledStartup).toEqual([]);
    expect(calls).toEqual(expect.arrayContaining(["off updater", "on updater"]));
  });

  it("concurrent checks share one run", async () => {
    let runs = 0;
    const { svc } = fakes({ firewall: async () => (runs++, { state: "on", detail: null, source: null }) });
    await Promise.all([svc.check(), svc.check(), svc.check()]);
    expect(runs).toBe(1);
  });

  it("a check that fails is reported as unknown, not as fine", async () => {
    const { svc, calls } = fakes({ firewall: async () => Promise.reject(new Error("no ufw")), encryption: async () => Promise.reject(new Error("no lsblk")) });
    const status = await svc.check();
    expect(status.firewall?.state).toBe("unknown");
    expect(status.encryption?.state).toBe("unknown");
    expect(calls[0]).toContain('"firewall":"unknown","encryption":"unknown"');
  });

  it("file integrity: only full paths can be watched; only real changes can be accepted", async () => {
    const { svc, integrityState } = fakes();
    expect((await svc.integrityAdd({ path: "/home/me/.ssh/authorized_keys" })).integrity.paths).toEqual(["/etc/hosts", "/home/me/.ssh/authorized_keys"]);
    await expect(svc.integrityAdd({ path: ".bashrc" })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.integrityAccept({ path: "/etc/hosts" })).rejects.toMatchObject({ code: "not_found" });
    integrityState.changes = [{ path: "/etc/hosts", kind: "modified", before: {} as never, after: {} as never, at: "2026-11-25T12:00:00Z" } as never];
    expect((await svc.integrityAccept({ path: "/etc/hosts" })).integrity.changes).toEqual([]);
    expect((await svc.integrityRemove({ path: "/etc/hosts" })).integrity.paths).toEqual(["/home/me/.ssh/authorized_keys"]);
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const POSTURE_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/posture.json");

it("posture replies match the fixture the Rust client decodes", async () => {
  const { svc, addStartup, integrityState } = fakes();
  await svc.check();
  addStartup(item("miner", ["Starts a program from a temporary or Downloads folder"]));
  await svc.check();
  await svc.startupOff({ id: "syncthing" });
  integrityState.lastCheck = "2026-11-25T12:00:00.000Z";
  integrityState.baseline = { "/etc/hosts": { path: "/etc/hosts", sha256: "c".repeat(64), size: 220, mtime: "2026-11-01T00:00:00.000Z" } as never };
  integrityState.changes = [{ path: "/etc/hosts", kind: "modified", before: integrityState.baseline["/etc/hosts"], after: { path: "/etc/hosts", sha256: "d".repeat(64), size: 260, mtime: "2026-11-25T11:00:00.000Z" }, at: "2026-11-25T12:00:00.000Z" } as never];
  const fixture = { status: svc.status() };
  if (process.env.UPDATE_FIXTURES) await writeFile(POSTURE_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(POSTURE_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});

describe.skipIf(process.platform === "win32")("file integrity over the daemon", () => {
  it("a watched file that changes is reported, then accepted", { timeout: 30_000 }, async () => {
    const dataDir = await temp();
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:9" }));
    const events: { event: string; payload: unknown }[] = [];
    const host = await createDaemonHost(dataDir, (event, payload) => events.push({ event, payload }));
    const h = createHandlers(host, () => {});
    const watched = join(dataDir, "hosts");
    await writeFile(watched, "127.0.0.1 localhost\n");
    await h["posture.integrity_add"]!({ path: watched });
    await writeFile(watched, "127.0.0.1 localhost\n203.0.113.9 bank.example\n");
    const after = (await h["posture.integrity_check"]!(undefined)) as { integrity: { changes: { path: string; kind: string }[] } };
    expect(after.integrity.changes).toEqual([expect.objectContaining({ path: watched, kind: "modified" })]);
    expect(events.find((e) => e.event === "alert")).toMatchObject({ payload: { kind: "integrity", count: 1 } });
    const accepted = (await h["posture.integrity_accept"]!({ path: watched })) as { integrity: { changes: unknown[] } };
    expect(accepted.integrity.changes).toEqual([]);
    host.integrity.stop();
  });
});
