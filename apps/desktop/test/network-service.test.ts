import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { type NetworkDeps, NetworkService } from "../src/core/network-service";
import { createDaemonHost } from "../src/daemon";
import type { CredentialResult } from "../src/engine/network/credentials";
import type { Inventory } from "../src/engine/network/inventory";
import type { Device, NetworkScan } from "../src/engine/network/types";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-net-"));
  folders.push(dir);
  return dir;
}

const device = (ip: string, mac: string, extra: Partial<Device> = {}): Device => ({ ip, mac, vendor: null, hostname: null, role: "device", services: [], trusted: false, firstSeen: null, ...extra });
const router = device("192.168.1.1", "aa:bb:cc:00:00:01", { role: "router", vendor: "Netgear", services: [{ port: 80, name: "http", banner: null }] });
const laptop = device("192.168.1.20", "aa:bb:cc:00:00:20", { role: "self", hostname: "my-laptop" });
const camera = device("192.168.1.30", "aa:bb:cc:00:00:30", { vendor: "Hikvision", hostname: "ipcam", services: [{ port: 23, name: "telnet", banner: "login:" }, { port: 80, name: "http", banner: null }] });
const tv = device("192.168.1.40", "aa:bb:cc:00:00:40", { vendor: "Samsung", hostname: "living-room-tv" });

function scanOf(devices: Device[], findings: NetworkScan["findings"] = [], at = "2026-11-25T12:00:00.000Z"): NetworkScan {
  return { startedAt: at, finishedAt: at, cidr: "192.168.1.0/24", gateway: "192.168.1.1", interface: "wlan0", wifi: { ssid: "Home", risk: "ok" }, devices: structuredClone(devices), router: null, findings, capabilities: { neighbours: "ok", mdns: "ok" }, newDevices: [] };
}

async function service(dir: string, scans: NetworkScan[], overrides: Partial<NetworkDeps> = {}) {
  let inventory: Inventory = {};
  let clock = Date.parse("2026-11-25T12:00:00Z");
  const events: { event: string; payload: unknown }[] = [];
  const queue = [...scans];
  let watch = true;
  const svc = new NetworkService({
    scanFile: join(dir, "network-scan.json"),
    loadInventory: async () => structuredClone(inventory),
    saveInventory: async (next) => {
      inventory = structuredClone(next);
    },
    scanNetwork: async (onProgress) => {
      onProgress(254, 254, "sweep");
      const next = queue.shift();
      if (!next) throw new Error("no more scans");
      return next;
    },
    checkHttp: async (ip, port) => ({ device: ip, service: `http:${port}`, defaultAccepted: false, user: null, tried: 5, stopped: null }),
    checkLineService: async (ip, port, s) => ({ device: ip, service: `${s}:${port}`, defaultAccepted: true, user: "admin", tried: 2, stopped: null }) as CredentialResult,
    watchOn: () => watch,
    emit: (event, payload) => events.push({ event, payload }),
    now: () => clock,
    ...overrides,
  });
  await svc.load();
  return { svc, events, inventory: () => inventory, advance: (ms: number) => (clock += ms), setWatch: (on: boolean) => (watch = on) };
}

describe("network service", () => {
  it("the first scan lists every device but raises no alarm", async () => {
    const dir = await temp();
    const { svc, events } = await service(dir, [scanOf([router, laptop, camera])]);
    const status = await svc.scan();
    expect(status.scan?.devices.map((d) => d.ip)).toEqual(["192.168.1.1", "192.168.1.20", "192.168.1.30"]);
    expect(status.scan?.devices[2]?.key).toBe("mac:aa:bb:cc:00:00:30");
    expect(status.changes).toMatchObject({ comparedWith: null, newDevices: [], gone: [], newRisks: [] });
    // The reply comes after the scan is done, not mid-scan.
    expect(status).toMatchObject({ scanning: false, progress: null });
    expect(events.map((e) => e.event)).toEqual(["network.progress", "network.scanned"]);
  });

  it("a rescan reports new devices, gone devices and new risks, and the change survives a restart", async () => {
    const dir = await temp();
    const risk = { severity: "high" as const, rule: "telnet_open", title: "Telnet is open on ipcam", detail: "", device: "192.168.1.30" };
    const { svc, events } = await service(dir, [scanOf([router, laptop, camera]), scanOf([router, laptop, tv], [risk], "2026-11-25T18:00:00.000Z")]);
    await svc.scan();
    const second = await svc.scan();
    expect(second.changes).toMatchObject({
      comparedWith: "2026-11-25T12:00:00.000Z",
      newDevices: ["mac:aa:bb:cc:00:00:40"],
      gone: [{ key: "mac:aa:bb:cc:00:00:30", ip: "192.168.1.30", name: "ipcam" }],
      newRisks: [{ rule: "telnet_open" }],
    });
    expect(events.find((e) => e.event === "alert")).toMatchObject({ payload: { kind: "network", newDevices: 1, newRisks: 1 } });
    // Saved: a restarted service still knows what changed and when it last scanned.
    const again = (await service(dir, [])).svc;
    expect(again.status().changes?.newDevices).toEqual(["mac:aa:bb:cc:00:00:40"]);
    expect(again.lastScanAt()).toBe("2026-11-25T18:00:00.000Z");
  });

  it("marking a device as known clears it from the new list; unknown keys are refused", async () => {
    const dir = await temp();
    const { svc, inventory } = await service(dir, [scanOf([router, laptop]), scanOf([router, laptop, tv])]);
    await svc.scan();
    await svc.scan();
    const status = await svc.trust({ key: "mac:aa:bb:cc:00:00:40", trusted: true });
    expect(status.changes?.newDevices).toEqual([]);
    expect(status.scan?.devices.find((d) => d.ip === "192.168.1.40")?.trusted).toBe(true);
    expect(inventory()["mac:aa:bb:cc:00:00:40"]?.trusted).toBe(true);
    await expect(svc.trust({ key: "ff:ff:ff:ff:ff:ff", trusted: true })).rejects.toMatchObject({ code: "not_found" });
    await expect(svc.trust({ key: "mac:aa:bb:cc:00:00:40", trusted: "yes" })).rejects.toMatchObject({ code: "bad_params" });
  });

  it("a known device coming back isn't news", async () => {
    const dir = await temp();
    const { svc, events } = await service(dir, [scanOf([router, tv]), scanOf([router]), scanOf([router, tv])]);
    await svc.scan();
    await svc.trust({ key: "mac:aa:bb:cc:00:00:40", trusted: true });
    await svc.scan();
    const third = await svc.scan();
    expect(third.changes?.newDevices).toEqual([]);
    expect(events.filter((e) => e.event === "alert")).toEqual([]);
  });

  it("one scan at a time", async () => {
    const dir = await temp();
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const { svc } = await service(dir, [], {
      scanNetwork: async () => {
        await gate;
        return scanOf([router]);
      },
    });
    const first = svc.scan();
    expect(svc.status().scanning).toBe(true);
    await expect(svc.scan()).rejects.toMatchObject({ code: "busy" });
    release();
    await first;
    expect(svc.status()).toMatchObject({ scanning: false, progress: null });
  });

  it("the scheduled rescan runs only when watching is on and the last scan is 6 hours old", async () => {
    const dir = await temp();
    const { svc, advance, setWatch } = await service(dir, [scanOf([router]), scanOf([router]), scanOf([router])]);
    expect(await svc.tick()).toBe(true); // never scanned
    advance(5 * 60 * 60 * 1000);
    expect(await svc.tick()).toBe(false);
    advance(60 * 60 * 1000);
    expect(svc.status().watch).toMatchObject({ on: true, everyHours: 6 });
    expect(await svc.tick()).toBe(true);
    setWatch(false);
    advance(7 * 60 * 60 * 1000);
    expect(await svc.tick()).toBe(false);
    expect(svc.status().watch.nextAt).toBeNull();
  });

  it("the default-password check needs consent, a scanned device and a login service", async () => {
    const dir = await temp();
    const { svc } = await service(dir, [scanOf([router, laptop, camera])]);
    await expect(svc.checkCredentials({ ip: "192.168.1.30", consent: true })).rejects.toMatchObject({ code: "not_found" });
    await svc.scan();
    await expect(svc.checkCredentials({ ip: "192.168.1.30" })).rejects.toMatchObject({ code: "consent_required" });
    // An address that wasn't in the scan can't be targeted.
    await expect(svc.checkCredentials({ ip: "8.8.8.8", consent: true })).rejects.toMatchObject({ code: "not_found" });
    await expect(svc.checkCredentials({ ip: "192.168.1.20", consent: true })).rejects.toMatchObject({ code: "unavailable" });
    const checked = await svc.checkCredentials({ ip: "192.168.1.30", consent: true });
    expect(checked.results.map((r) => r.service)).toEqual(["http:80", "telnet:23"]);
    expect(checked.results[1]).toMatchObject({ defaultAccepted: true, user: "admin" });
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const NETWORK_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/network.json");

it("network replies match the fixture the Rust client decodes", async () => {
  const dir = await temp();
  const risk = { severity: "critical" as const, rule: "default_login", title: "ipcam accepts a factory default login", detail: "Change the admin password on the camera.", device: "192.168.1.30" };
  const first = scanOf([router, laptop, camera]);
  first.router = { ip: "192.168.1.1", adminHttp: true, hint: "Netgear", portForwards: [{ external: 8080, internal: "192.168.1.30:80", protocol: "TCP", description: "camera" }], upnp: true, dns: [{ address: "192.168.1.1", known: false }] };
  const second = { ...scanOf([router, laptop, tv], [risk], "2026-11-25T18:00:00.000Z"), router: first.router };
  const { svc } = await service(dir, [first, second]);
  await svc.scan();
  const status = await svc.scan();
  const credentials = await svc.trust({ key: "mac:aa:bb:cc:00:00:20", trusted: true }).then(() => ({ ip: "192.168.1.1", results: [{ device: "192.168.1.1", service: "http", defaultAccepted: false, user: null, tried: 5, stopped: null }] }));
  const fixture = { status, credentials };
  if (process.env.UPDATE_FIXTURES) await writeFile(NETWORK_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(NETWORK_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});

describe.skipIf(process.platform === "win32")("network scanning over the daemon", () => {
  it("scans this computer with the real engine (no real network touched) and marks it known", { timeout: 90_000 }, async () => {
    const dataDir = await temp();
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:9", networkWatch: false }));
    const before = process.env.QALAA_TEST_NETWORK_HOST;
    process.env.QALAA_TEST_NETWORK_HOST = "127.0.0.1";
    try {
      const host = await createDaemonHost(dataDir);
      const h = createHandlers(host, () => {});
      const status = (await h["network.scan"]!(undefined)) as { scan: { devices: { ip: string; key: string }[] }; watch: { on: boolean } };
      const me = status.scan.devices.find((d) => d.ip === "127.0.0.1");
      expect(me).toBeDefined();
      expect(status.watch.on).toBe(false);
      const trusted = (await h["network.trust"]!({ key: me!.key, trusted: true })) as { scan: { devices: { ip: string; trusted: boolean }[] } };
      expect(trusted.scan.devices.find((d) => d.ip === "127.0.0.1")?.trusted).toBe(true);
      // Home sees the real scan time.
      const home = (await h["home.get"]!(undefined)) as { checks: { id: string; checkedAt: string | null }[] };
      expect(home.checks.find((c) => c.id === "network")?.checkedAt).toBeTruthy();
    } finally {
      if (before === undefined) delete process.env.QALAA_TEST_NETWORK_HOST;
      else process.env.QALAA_TEST_NETWORK_HOST = before;
    }
  });
});
