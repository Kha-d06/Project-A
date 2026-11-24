/**
 * Safe DNS as a service, shared by the background service and the classic app:
 * keeps its state, runs the local proxy while on, switches the system resolver
 * through the consent prompt, and refreshes the downloaded domain list.
 */
import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";

import { describeSwitch, parseNetworkServices, parseResolvConf, parseScutilDns, parseWindowsServers, proxyPort, switchCommand } from "../engine/dns-system";
import type { ElevatedCommand } from "../engine/listeners";
import { SafeDnsProxy, type SafeDnsStats, UPSTREAMS, type UpstreamId } from "../engine/safe-dns";
import { runElevated } from "./listener-service";
import { IpcError } from "./protocol";
import { atomicWrite } from "./atomic-write";

export interface SafeDnsState {
  enabled: boolean;
  upstream: UpstreamId;
  /** The network's own DNS servers, recorded when Safe DNS was turned on. */
  fallback: string[];
  blocklist: string[];
  blocklistAt: string | null;
}

const EMPTY: SafeDnsState = { enabled: false, upstream: "quad9", fallback: [], blocklist: [], blocklistAt: null };
const REFRESH_MS = 6 * 60 * 60 * 1000;

export interface SafeDnsDepsHost {
  platform: NodeJS.Platform;
  exec?: (command: ElevatedCommand) => Promise<void>;
  /** The network's DNS servers right now (before switching). */
  currentServers?: () => Promise<string[]>;
  macServices?: () => Promise<string[]>;
  fetchDomains?: () => Promise<string[]>;
  available?: () => Promise<boolean>;
  /** For tests: where the proxy listens. */
  port?: number;
  proxy?: (deps: ConstructorParameters<typeof SafeDnsProxy>[0]) => SafeDnsProxy;
}

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve) => {
    execFile(command, args, { timeout: 20_000, windowsHide: true }, (_e, stdout) => resolve(String(stdout ?? "")));
  });
}

export function defaultCurrentServers(platform: NodeJS.Platform): () => Promise<string[]> {
  if (platform === "win32") {
    return async () => parseWindowsServers(await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]));
  }
  if (platform === "darwin") return async () => parseScutilDns(await run("scutil", ["--dns"]));
  return async () => parseResolvConf(await readFile("/run/systemd/resolve/resolv.conf", "utf8").catch(() => ""));
}

export function defaultAvailable(platform: NodeJS.Platform): () => Promise<boolean> {
  if (platform === "linux") return () => stat("/run/systemd/resolve/stub-resolv.conf").then(() => true).catch(() => false);
  return async () => platform === "win32" || platform === "darwin";
}

export class SafeDnsService {
  private state: SafeDnsState = EMPTY;
  private proxy: SafeDnsProxy | null = null;
  private blockset = new Set<string>();
  private readonly exec: (command: ElevatedCommand) => Promise<void>;
  private readonly currentServers: () => Promise<string[]>;
  private readonly macServices: () => Promise<string[]>;
  private readonly available: () => Promise<boolean>;
  private supported = false;

  constructor(
    private readonly file: string,
    private readonly serverUrl: () => string,
    private readonly deps: SafeDnsDepsHost,
  ) {
    this.exec = deps.exec ?? runElevated;
    this.currentServers = deps.currentServers ?? defaultCurrentServers(deps.platform);
    this.macServices = deps.macServices ?? (async () => parseNetworkServices(await run("networksetup", ["-listallnetworkservices"])));
    this.available = deps.available ?? defaultAvailable(deps.platform);
  }

  async load(): Promise<void> {
    try {
      this.state = { ...EMPTY, ...(JSON.parse(await readFile(this.file, "utf8")) as Partial<SafeDnsState>) };
    } catch {
      this.state = EMPTY;
    }
    this.blockset = new Set(this.state.blocklist);
    this.supported = await this.available();
  }

  private save(): Promise<void> {
    return atomicWrite(this.file, JSON.stringify(this.state));
  }

  isOn(): boolean {
    return this.state.enabled;
  }

  isSupported(): boolean {
    return this.supported;
  }

  /** Starts the proxy if Safe DNS was left on (the system already points at it). */
  async resume(): Promise<void> {
    if (this.state.enabled && !this.proxy) await this.startProxy().catch(() => undefined);
    void this.refreshDomains().catch(() => undefined);
  }

  private async startProxy(): Promise<void> {
    const deps = {
      blocklist: () => this.blockset,
      upstream: UPSTREAMS[this.state.upstream].url,
      fallback: () => this.state.fallback,
    };
    const proxy = this.deps.proxy ? this.deps.proxy(deps) : new SafeDnsProxy(deps);
    await proxy.start(this.deps.port ?? proxyPort(this.deps.platform));
    this.proxy = proxy;
  }

  async refreshDomains(force = false): Promise<void> {
    const fresh = this.state.blocklistAt && Date.now() - Date.parse(this.state.blocklistAt) < REFRESH_MS;
    if (fresh && !force) return;
    const fetchDomains =
      this.deps.fetchDomains ??
      (async () => {
        const response = await fetch(`${this.serverUrl().replace(/\/$/, "")}/api/v1/intelligence/domain-list`, { signal: AbortSignal.timeout(30_000) });
        if (!response.ok) throw new Error(`The server answered ${response.status}`);
        return ((await response.json()) as { hosts: string[] }).hosts;
      });
    const hosts = (await fetchDomains()).map((h) => h.toLowerCase()).filter((h) => /^[a-z0-9.-]+$/.test(h));
    this.state = { ...this.state, blocklist: hosts, blocklistAt: new Date().toISOString() };
    this.blockset = new Set(hosts);
    await this.save();
  }

  /** Turns Safe DNS on or off. Shows the system's consent prompt; a refusal changes nothing. */
  async setEnabled(on: boolean): Promise<{ change: string }> {
    if (!this.supported) throw new IpcError("unavailable", "Safe DNS needs systemd-resolved on Linux, or Windows or macOS.");
    const upstream = UPSTREAMS[this.state.upstream].name;
    if (on) {
      const fallback = (await this.currentServers()).filter((s) => s !== "127.0.0.1");
      this.state = { ...this.state, fallback };
      if (!this.proxy) await this.startProxy();
      try {
        const services = this.deps.platform === "darwin" ? await this.macServices() : [];
        await this.exec(switchCommand(this.deps.platform, true, fallback, services));
      } catch (error) {
        await this.proxy?.stop();
        this.proxy = null;
        throw error;
      }
      this.state = { ...this.state, enabled: true };
    } else {
      const services = this.deps.platform === "darwin" ? await this.macServices() : [];
      await this.exec(switchCommand(this.deps.platform, false, [], services));
      await this.proxy?.stop();
      this.proxy = null;
      this.state = { ...this.state, enabled: false };
    }
    await this.save();
    void this.refreshDomains().catch(() => undefined);
    return { change: describeSwitch(this.deps.platform, on, upstream) };
  }

  status(): { enabled: boolean; supported: boolean; running: boolean; upstream: string; domains: number; stats: SafeDnsStats | null; fallback: string[] } {
    return {
      enabled: this.state.enabled,
      supported: this.supported,
      running: this.proxy?.running() ?? false,
      upstream: UPSTREAMS[this.state.upstream].name,
      domains: this.blockset.size,
      stats: this.proxy?.stats ?? null,
      fallback: this.state.fallback,
    };
  }

  async stop(): Promise<void> {
    await this.proxy?.stop();
    this.proxy = null;
  }
}
