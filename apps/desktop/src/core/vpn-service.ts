/**
 * Qalaa's self-hosted WireGuard VPN for any interface over qalaa-ipc (until now
 * only inside the Electron window). Engines unchanged (engine/vpn.ts and
 * engine/vpn-guard.ts):
 *
 * - Set up: a key pair made on this computer (the private key never leaves it),
 *   the public key registered with the linked account's server, the tunnel
 *   saved and imported into NetworkManager / WireGuard.
 * - Connect and disconnect.
 * - Kill switch (Linux, nftables): only the tunnel and the VPN server itself
 *   may carry traffic, optionally the local network too. Installing or removing
 *   it asks for the password (pkexec); declined leaves the setting as it was.
 * - Split tunnelling: everything (full), everything except some ranges
 *   (exclude), or only some ranges (only). Every range is checked as an IPv4 or
 *   IPv6 CIDR before it can reach the tunnel file. Changing it rebuilds a saved
 *   tunnel straight away.
 * - Auto-connect on Wi-Fi that isn't on the trusted list (Linux): checked every
 *   20 seconds; it connects once per untrusted network, and never fights the
 *   person turning the VPN off again on the same network.
 */
import { readFile, stat } from "node:fs/promises";
import { isIP } from "node:net";

import type { LinkedAccount } from "../engine/account";
import type { WifiStatus } from "../engine/system";
import type { KeyPair, PeerConfig, TunnelState } from "../engine/vpn";
import type { SplitMode } from "../engine/vpn-guard";
import { IpcError } from "./protocol";

export const AUTO_CONNECT_MS = 20_000;
const MAX_RANGES = 40;
const MAX_TRUSTED = 40;

export interface VpnSettings {
  vpnKillSwitch: boolean;
  vpnKillSwitchAllowLan: boolean;
  vpnSplitMode: SplitMode;
  vpnSplitCidrs: string[];
  vpnAutoConnect: boolean;
  vpnTrustedNetworks: string[];
}

export interface VpnStatus {
  platform: NodeJS.Platform;
  /** This computer is linked to a Qalaa account (needed to set up a tunnel). */
  linked: boolean;
  /** A tunnel file is saved on this computer. */
  saved: boolean;
  state: TunnelState;
  /** The kill switch and auto-connect need nftables and NetworkManager (Linux). */
  guardCapable: boolean;
  killSwitch: boolean;
  allowLan: boolean;
  splitMode: SplitMode;
  splitCidrs: string[];
  autoConnect: boolean;
  trusted: string[];
  /** The Wi-Fi network auto-connect last acted on, if any. */
  autoConnectedOn: string | null;
}

export interface VpnDeps {
  platform: NodeJS.Platform;
  tunnelFile: string;
  account: () => Promise<LinkedAccount | null>;
  settings: () => VpnSettings;
  saveSettings: (changes: Partial<VpnSettings>) => Promise<void>;
  tunnel: {
    state(): Promise<TunnelState>;
    keyPair(): KeyPair;
    requestPeer(account: LinkedAccount, publicKey: string): Promise<PeerConfig>;
    build(config: PeerConfig, privateKey: string): string;
    save(text: string): Promise<string>;
    importFile(file: string): Promise<void>;
    connect(): Promise<void>;
    disconnect(): Promise<void>;
  };
  guard: {
    capable(): boolean;
    applySplit(config: string, mode: SplitMode, cidrs: string[]): string;
    killSwitchScript(endpointHost: string, allowLan: boolean): string;
    removeKillSwitchScript(): string;
    shouldAutoConnect(wifi: WifiStatus, policy: { enabled: boolean; trusted: string[] }): boolean;
  };
  /** Runs a root script after the system's password prompt (pkexec). */
  elevate: (script: string) => Promise<void>;
  wifi: () => Promise<WifiStatus>;
  emit: (event: "alert", payload: unknown) => void;
}

/** "10.0.0.0/8" or "fd00::/8": an address and a prefix that fits it. */
export function validCidr(value: string): boolean {
  const [address, prefix, extra] = value.trim().split("/");
  if (!address || prefix === undefined || extra !== undefined || !/^\d{1,3}$/.test(prefix)) return false;
  const family = isIP(address);
  const bits = Number(prefix);
  return (family === 4 && bits <= 32) || (family === 6 && bits <= 128);
}

function failed(error: unknown): IpcError {
  return error instanceof IpcError ? error : new IpcError("failed", (error instanceof Error ? error.message : String(error)).slice(0, 300));
}

export class VpnService {
  private autoActedOn: string | null = null;
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly deps: VpnDeps) {}

  async status(): Promise<VpnStatus> {
    const s = this.deps.settings();
    const saved = await stat(this.deps.tunnelFile).then(() => true, () => false);
    return {
      platform: this.deps.platform,
      linked: (await this.deps.account().catch(() => null)) !== null,
      saved,
      state: await this.deps.tunnel.state().catch(() => "unsupported" as const),
      guardCapable: this.deps.guard.capable(),
      killSwitch: s.vpnKillSwitch,
      allowLan: s.vpnKillSwitchAllowLan,
      splitMode: s.vpnSplitMode,
      splitCidrs: s.vpnSplitCidrs,
      autoConnect: s.vpnAutoConnect,
      trusted: s.vpnTrustedNetworks,
      autoConnectedOn: this.autoActedOn,
    };
  }

  /** New keys made here, the public one registered with the server, the tunnel saved and imported. */
  async setup(): Promise<VpnStatus> {
    const account = await this.deps.account();
    if (!account) throw new IpcError("not_linked", "Link this computer to your Qalaa account first.");
    const s = this.deps.settings();
    try {
      const keys = this.deps.tunnel.keyPair();
      const peer = await this.deps.tunnel.requestPeer(account, keys.publicKey);
      const text = this.deps.guard.applySplit(this.deps.tunnel.build(peer, keys.privateKey), s.vpnSplitMode, s.vpnSplitCidrs);
      const file = await this.deps.tunnel.save(text);
      if ((await this.deps.tunnel.state()) !== "unsupported") await this.deps.tunnel.importFile(file);
      // A new server address: the kill switch's allow rule must follow it.
      if (s.vpnKillSwitch) await this.applyKillSwitch();
    } catch (error) {
      throw failed(error);
    }
    return this.status();
  }

  async connect(): Promise<VpnStatus> {
    await this.requireTunnel();
    await this.deps.tunnel.connect().catch((error: unknown) => {
      throw failed(error);
    });
    return this.status();
  }

  async disconnect(): Promise<VpnStatus> {
    await this.deps.tunnel.disconnect().catch((error: unknown) => {
      throw failed(error);
    });
    return this.status();
  }

  async setKillSwitch(params: unknown): Promise<VpnStatus> {
    const on = (params as { on?: unknown } | undefined)?.on;
    if (typeof on !== "boolean") throw new IpcError("bad_params", '"on" must be true or false.');
    if (!this.deps.guard.capable()) throw new IpcError("unavailable", "The kill switch needs nftables and is available on Linux only.");
    try {
      if (on) await this.applyKillSwitch();
      else await this.deps.elevate(this.deps.guard.removeKillSwitchScript());
    } catch (error) {
      throw failed(error); // the password prompt was declined, or nft failed: nothing saved
    }
    await this.deps.saveSettings({ vpnKillSwitch: on });
    return this.status();
  }

  /** Split tunnelling, LAN access with the kill switch, auto-connect and trusted networks. */
  async setGuard(params: unknown): Promise<VpnStatus> {
    const p = (params ?? {}) as Record<string, unknown>;
    const changes: Partial<VpnSettings> = {};
    if (p.splitMode !== undefined) {
      if (p.splitMode !== "full" && p.splitMode !== "exclude" && p.splitMode !== "only") throw new IpcError("bad_params", 'Expected "full", "exclude" or "only".');
      changes.vpnSplitMode = p.splitMode;
    }
    if (p.splitCidrs !== undefined) {
      if (!Array.isArray(p.splitCidrs) || p.splitCidrs.length > MAX_RANGES) throw new IpcError("bad_params", `Expected up to ${MAX_RANGES} address ranges.`);
      const ranges = p.splitCidrs.map((c) => (typeof c === "string" ? c.trim() : ""));
      const bad = ranges.find((c) => !validCidr(c));
      if (bad !== undefined) throw new IpcError("bad_params", `"${bad.slice(0, 60)}" isn't an address range like 192.168.1.0/24.`);
      changes.vpnSplitCidrs = [...new Set(ranges)];
    }
    for (const [key, setting] of [["allowLan", "vpnKillSwitchAllowLan"], ["autoConnect", "vpnAutoConnect"]] as const) {
      if (p[key] === undefined) continue;
      if (typeof p[key] !== "boolean") throw new IpcError("bad_params", `"${key}" must be true or false.`);
      changes[setting] = p[key] as boolean;
    }
    if (p.trusted !== undefined) {
      if (!Array.isArray(p.trusted) || p.trusted.length > MAX_TRUSTED) throw new IpcError("bad_params", `Expected up to ${MAX_TRUSTED} network names.`);
      const names = p.trusted.map((n) => (typeof n === "string" ? n.trim() : ""));
      if (names.some((n) => !n || Buffer.byteLength(n) > 32)) throw new IpcError("bad_params", "A Wi-Fi name is 1 to 32 bytes.");
      changes.vpnTrustedNetworks = [...new Set(names)];
    }
    if (changes.vpnAutoConnect && !this.deps.guard.capable()) throw new IpcError("unavailable", "Auto-connect is available on Linux only for now.");
    if (!Object.keys(changes).length) throw new IpcError("bad_params", "Nothing to change.");
    const before = this.deps.settings();
    await this.deps.saveSettings(changes);
    const after = this.deps.settings();
    const routing = before.vpnSplitMode !== after.vpnSplitMode || before.vpnSplitCidrs.join(",") !== after.vpnSplitCidrs.join(",");
    if (routing) await this.rebuildTunnel();
    if (before.vpnKillSwitchAllowLan !== after.vpnKillSwitchAllowLan && after.vpnKillSwitch) await this.applyKillSwitch().catch((error: unknown) => {
      throw failed(error);
    });
    this.applyAutoConnect();
    return this.status();
  }

  /** Starts or stops the Wi-Fi watch to match the setting (the daemon calls this at start). */
  applyAutoConnect(): void {
    const want = this.deps.settings().vpnAutoConnect && this.deps.guard.capable();
    if (want && !this.timer) {
      this.timer = setInterval(() => void this.autoTick().catch(() => undefined), AUTO_CONNECT_MS);
      this.timer.unref();
      void this.autoTick().catch(() => undefined);
    } else if (!want && this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** One auto-connect check: connects once on an untrusted network. Returns true when it connected. */
  async autoTick(): Promise<boolean> {
    const s = this.deps.settings();
    if (!s.vpnAutoConnect || !this.deps.guard.capable()) return false;
    const state = await this.deps.tunnel.state();
    if (state === "unsupported" || state === "not_imported") return false;
    const wifi = await this.deps.wifi();
    const want = this.deps.guard.shouldAutoConnect(wifi, { enabled: true, trusted: s.vpnTrustedNetworks });
    if (!want) {
      this.autoActedOn = null; // back on a trusted network (or none): may act again later
      return false;
    }
    const network = wifi.ssid ?? "";
    // Once per network: if the person turns it off again here, leave it off.
    if (state !== "disconnected" || this.autoActedOn === network) return false;
    this.autoActedOn = network;
    await this.deps.tunnel.connect();
    this.deps.emit("alert", { kind: "vpn", autoConnected: true, network: wifi.ssid });
    return true;
  }

  private async requireTunnel(): Promise<void> {
    if (!(await stat(this.deps.tunnelFile).then(() => true, () => false))) throw new IpcError("not_set_up", "Set up the VPN on this computer first.");
  }

  private async endpointHost(): Promise<string> {
    const text = await readFile(this.deps.tunnelFile, "utf8").catch(() => "");
    return /^Endpoint\s*=\s*([^\s:]+)/m.exec(text)?.[1] ?? "0.0.0.0";
  }

  private async applyKillSwitch(): Promise<void> {
    const s = this.deps.settings();
    await this.deps.elevate(this.deps.guard.killSwitchScript(await this.endpointHost(), s.vpnKillSwitchAllowLan));
  }

  /** New routing takes effect at once on a saved tunnel; with none, at the next setup. */
  private async rebuildTunnel(): Promise<void> {
    const text = await readFile(this.deps.tunnelFile, "utf8").catch(() => null);
    if (text === null) return;
    const s = this.deps.settings();
    const file = await this.deps.tunnel.save(this.deps.guard.applySplit(text, s.vpnSplitMode, s.vpnSplitCidrs));
    if ((await this.deps.tunnel.state()) !== "unsupported") await this.deps.tunnel.importFile(file).catch((error: unknown) => {
      throw failed(error);
    });
  }
}
