import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { buildHome } from "../src/core/home";
import { ListenerService } from "../src/core/listener-service";
import type { ElevatedCommand } from "../src/engine/listeners";
import type { ListeningPort } from "../src/engine/security";

const port = (p: number, process: string, exposed = true): ListeningPort => ({ port: p, address: exposed ? "0.0.0.0" : "127.0.0.1", process, pid: 1, exposed, risk: p === 23 ? "Telnet sends everything unencrypted" : null });

async function setup(platform: NodeJS.Platform = "linux") {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-listeners-"));
  let ports: ListeningPort[] = [port(22, "sshd")];
  const events: { event: string; payload: unknown }[] = [];
  const ran: ElevatedCommand[] = [];
  const service = new ListenerService(join(dir, "listeners.json"), platform, async () => ports, (event, payload) => events.push({ event, payload }), async (c) => void ran.push(c));
  await service.load();
  return { dir, service, events, ran, setPorts: (next: ListeningPort[]) => (ports = next) };
}

describe("listener service", () => {
  it("alerts once per new listener, through trust and block", async () => {
    const { dir, service, events, ran, setPorts } = await setup();
    expect(await service.check()).toEqual([]);
    expect(events).toEqual([]);

    setPorts([port(22, "sshd"), port(23, "telnetd")]);
    await service.check();
    await service.check();
    expect(events).toEqual([{ event: "alert", payload: { kind: "listener", key: "telnetd|23|net", port: 23, process: "telnetd", risk: "Telnet sends everything unencrypted" } }]);
    expect(service.newCount()).toBe(1);
    expect(service.status().listeners.find((l) => l.port === 23)?.fresh).toBe(true);

    const blocked = await service.block(23, true);
    expect(ran).toHaveLength(1);
    expect(ran[0]?.command).toBe("pkexec");
    expect(ran[0]?.args[2]).toContain("elements = { 23 }");
    expect(blocked.blockedPorts).toEqual([23]);
    expect(blocked.change).toMatch(/Block incoming connections from other machines to port 23/);
    expect(service.newCount()).toBe(0);
    // Persisted for the next start.
    expect(JSON.parse(await readFile(join(dir, "listeners.json"), "utf8")).blockedPorts).toEqual([23]);

    const undone = await service.block(23, false);
    expect(undone.blockedPorts).toEqual([]);
    expect(ran[1]?.args[2]).toBe("nft -f - <<'QALAA'\ntable inet qalaa_ports\ndelete table inet qalaa_ports\nQALAA");

    setPorts([port(22, "sshd"), port(8000, "python3")]);
    await service.check();
    await service.trust("python3|8000|net");
    expect(service.newCount()).toBe(0);
  });

  it("a declined system prompt changes nothing", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-listeners-"));
    const service = new ListenerService(join(dir, "l.json"), "win32", async () => [], () => {}, async () => {
      throw new Error("The operation was canceled by the user.");
    });
    await expect(service.block(4444, true)).rejects.toThrow(/canceled/);
    expect(service.status().blockedPorts).toEqual([]);
  });

  it("is served over IPC, validates input, and puts an action on Home", async () => {
    const { service, setPorts } = await setup();
    await service.check();
    setPorts([port(22, "sshd"), port(4444, "nc")]);
    const base = { now: new Date(), platform: "linux" as const, watchEnabled: true, onAccessScan: false, ransomwareWatch: true, networkWatch: true, cloudLookup: false, signatures: { count: 1, updatedAt: new Date().toISOString(), error: null }, lastScanAt: new Date().toISOString(), lastNetworkScanAt: new Date().toISOString(), lastBackupAt: new Date().toISOString(), lastBackupError: null, backupConfigured: true, quarantineCount: 0, recentThreats: 0, ransomwareAlertAt: null, updateAvailable: null, silentUntil: null };
    const host = { version: "t", homeInput: async () => ({ ...base, newListeners: service.newCount() }), updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, listeners: service };
    const handlers = createHandlers(host, () => {});
    const status = (await handlers["listeners.check"]?.(undefined)) as { listeners: { port: number; fresh: boolean }[] };
    expect(status.listeners.find((l) => l.port === 4444)?.fresh).toBe(true);
    const home = buildHome(await host.homeInput());
    expect(home.actions[0]?.id).toBe("review_listeners");
    await expect(handlers["listeners.block"]?.({ port: 0, block: true })).rejects.toThrow(/1 to 65535/);
    await expect(handlers["listeners.block"]?.({ port: 22 })).rejects.toThrow(/true or false/);
    await expect(handlers["listeners.trust"]?.({ key: 5 })).rejects.toThrow();
    const without = createHandlers({ ...host, listeners: undefined }, () => {});
    await expect(without["listeners.get"]?.(undefined)).rejects.toThrow(/aren't running/);
  });
});

describe("overlapping checks (slow lsof on macOS)", () => {
  it("share one look, so a port opened after the first look starts is never absorbed into the quiet baseline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-listeners-"));
    const events: unknown[] = [];
    let ports: ListeningPort[] = [port(22, "sshd")];
    let release!: () => void;
    const slow = new Promise<void>((r) => (release = r));
    let calls = 0;
    const service = new ListenerService(join(dir, "l.json"), "darwin", async () => {
      calls++;
      if (calls === 1) await slow;
      return ports;
    }, (_e, p) => events.push(p));
    await service.load();
    const first = service.check(); // the daemon's own start-up look
    const second = service.check(); // the harness asks while it is still running
    release();
    await Promise.all([first, second]);
    expect(calls).toBe(1);
    ports = [port(22, "sshd"), port(48731, "Python")];
    const fresh = await service.check();
    expect(fresh.map((l) => l.port)).toEqual([48731]);
    expect(events).toHaveLength(1);
  });
});
