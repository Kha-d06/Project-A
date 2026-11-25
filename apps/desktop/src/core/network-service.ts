/**
 * The home network scanner for any interface over qalaa-ipc (until now it ran
 * only inside the Electron window). The engine is unchanged: it reads the
 * system's neighbour table, makes plain TCP connections and listens for the
 * standard discovery multicasts, as an ordinary user.
 *
 * What this service adds around it:
 * - One scan at a time (a second request is refused as "busy"), progress as
 *   network.progress events.
 * - The last scan is saved, so "what changed" survives a restart: new devices,
 *   devices no longer seen, and new high or critical risks since that scan.
 * - An alert only for real change: never on the first scan (everything is new
 *   then), and never for a device the person marked as known.
 * - The scheduled rescan (every 6 hours when Watch my network is on).
 * - The default-password check runs only with the person's consent, only
 *   against a device from the last scan, and only on its login services.
 *   Wording is "no default password accepted", never "secure".
 */
import { readFile, writeFile } from "node:fs/promises";

import type { CredentialResult } from "../engine/network/credentials";
import { type Inventory, annotate, deviceKey, reconcile, setTrusted } from "../engine/network/inventory";
import { newRiskyFindings } from "../engine/network/scan";
import type { Device, NetworkFinding, NetworkScan } from "../engine/network/types";
import { IpcError } from "./protocol";

export const RESCAN_HOURS = 6;
const HOUR = 60 * 60 * 1000;
const PROGRESS_EVERY_MS = 250;

export interface NetworkChanges {
  /** The scan this one was compared with, or null on the first scan. */
  comparedWith: string | null;
  /** Keys of devices not seen before (untrusted ones only). */
  newDevices: string[];
  /** Devices in the previous scan that didn't answer this time. */
  gone: { key: string; ip: string; name: string | null }[];
  /** High or critical findings that weren't in the previous scan. */
  newRisks: NetworkFinding[];
}

export interface NetworkStatus {
  scanning: boolean;
  progress: { done: number; total: number; phase: string } | null;
  /** The last scan, with each device's inventory key. */
  scan: (NetworkScan & { devices: (Device & { key: string })[] }) | null;
  changes: NetworkChanges | null;
  watch: { on: boolean; everyHours: number; nextAt: string | null };
}

export interface NetworkDeps {
  scanFile: string;
  loadInventory: () => Promise<Inventory>;
  saveInventory: (inventory: Inventory) => Promise<void>;
  scanNetwork: (onProgress: (done: number, total: number, phase: string) => void) => Promise<NetworkScan>;
  checkHttp: (ip: string, port: number) => Promise<CredentialResult>;
  checkLineService: (ip: string, port: number, service: "telnet" | "ftp") => Promise<CredentialResult>;
  watchOn: () => boolean;
  emit: (event: "network.progress" | "network.scanned" | "alert", payload: unknown) => void;
  now?: () => number;
}

export class NetworkService {
  private last: NetworkScan | null = null;
  private changes: NetworkChanges | null = null;
  private scanning = false;
  private progress: NetworkStatus["progress"] = null;
  private lastProgressAt = 0;
  private readonly now: () => number;

  constructor(private readonly deps: NetworkDeps) {
    this.now = deps.now ?? Date.now;
  }

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.deps.scanFile, "utf8")) as { scan?: NetworkScan; changes?: NetworkChanges };
      this.last = saved.scan && Array.isArray(saved.scan.devices) ? saved.scan : null;
      this.changes = saved.changes ?? null;
    } catch {
      this.last = null;
    }
  }

  lastScanAt(): string | null {
    return this.last?.finishedAt ?? null;
  }

  status(): NetworkStatus {
    const nextAt = this.deps.watchOn() ? new Date((this.last ? Date.parse(this.last.finishedAt) : this.now()) + RESCAN_HOURS * HOUR).toISOString() : null;
    return {
      scanning: this.scanning,
      progress: this.progress,
      scan: this.last ? { ...this.last, devices: this.last.devices.map((d) => ({ ...d, key: deviceKey(d) })) } : null,
      changes: this.changes,
      watch: { on: this.deps.watchOn(), everyHours: RESCAN_HOURS, nextAt },
    };
  }

  async scan(): Promise<NetworkStatus> {
    if (this.scanning) throw new IpcError("busy", "A network scan is already running.");
    this.scanning = true;
    this.progress = { done: 0, total: 0, phase: "sweep" };
    try {
      const inventory = await this.deps.loadInventory();
      const firstEver = Object.keys(inventory).length === 0;
      const scan = await this.deps.scanNetwork((done, total, phase) => {
        this.progress = { done, total, phase };
        if (this.now() - this.lastProgressAt >= PROGRESS_EVERY_MS) {
          this.lastProgressAt = this.now();
          this.deps.emit("network.progress", this.progress);
        }
      });
      const { inventory: updated, newKeys } = reconcile(inventory, scan.devices, new Date(this.now()).toISOString());
      await this.deps.saveInventory(updated);
      scan.devices = annotate(scan.devices, updated);
      // A device the person already marked as known isn't news, whatever the inventory says.
      const fresh = firstEver ? [] : newKeys.filter((k) => !updated[k]?.trusted);
      scan.newDevices = fresh;
      const previous = this.last;
      const nowKeys = new Set(scan.devices.map(deviceKey));
      this.changes = {
        comparedWith: previous?.finishedAt ?? null,
        newDevices: fresh,
        gone: (previous?.devices ?? []).filter((d) => d.role === "device" && !nowKeys.has(deviceKey(d))).map((d) => ({ key: deviceKey(d), ip: d.ip, name: d.hostname ?? d.vendor })),
        newRisks: previous ? newRiskyFindings(previous, scan) : [], // high or critical, not in the previous scan
      };
      this.last = scan;
      await writeFile(this.deps.scanFile, JSON.stringify({ scan, changes: this.changes }));
      if (this.changes.newDevices.length || this.changes.newRisks.length) {
        this.deps.emit("alert", { kind: "network", newDevices: this.changes.newDevices.length, newRisks: this.changes.newRisks.length });
      }
      this.deps.emit("network.scanned", { devices: scan.devices.length, findings: scan.findings.length });
    } finally {
      this.scanning = false;
      this.progress = null;
    }
    // Built after the scan is marked finished, so the reply doesn't say it's still running.
    return this.status();
  }

  /** The scheduled rescan: when Watch my network is on and the last scan is 6 hours old. */
  async tick(): Promise<boolean> {
    if (!this.deps.watchOn() || this.scanning) return false;
    const lastAt = this.last ? Date.parse(this.last.finishedAt) : 0;
    if (this.now() - lastAt < RESCAN_HOURS * HOUR) return false;
    await this.scan();
    return true;
  }

  async trust(params: unknown): Promise<NetworkStatus> {
    const { key, trusted } = (params ?? {}) as { key?: unknown; trusted?: unknown };
    if (typeof key !== "string" || !key || key.length > 64) throw new IpcError("bad_params", "Expected a device key.");
    if (typeof trusted !== "boolean") throw new IpcError("bad_params", '"trusted" must be true or false.');
    const inventory = await this.deps.loadInventory();
    if (!inventory[key]) throw new IpcError("not_found", "That device isn't in the list. Scan the network first.");
    const next = setTrusted(inventory, key, trusted);
    await this.deps.saveInventory(next);
    if (this.last) this.last = { ...this.last, devices: annotate(this.last.devices, next) };
    if (trusted && this.changes) this.changes = { ...this.changes, newDevices: this.changes.newDevices.filter((k) => k !== key) };
    return this.status();
  }

  /**
   * Tries each login service's factory default passwords (at most a few, stopping
   * at a lockout). Needs consent, and only for a device from the last scan, so
   * this can't be pointed at an address elsewhere.
   */
  async checkCredentials(params: unknown): Promise<{ ip: string; results: CredentialResult[] }> {
    const { ip, consent } = (params ?? {}) as { ip?: unknown; consent?: unknown };
    if (consent !== true) throw new IpcError("consent_required", "The default-password check needs your consent first.");
    const device = this.last?.devices.find((d) => d.ip === ip);
    if (!device) throw new IpcError("not_found", "Scan the network first, then check a device from the list.");
    const has = (port: number) => device.services.some((s) => s.port === port);
    const results: CredentialResult[] = [];
    if (has(80) || has(8080)) results.push(await this.deps.checkHttp(device.ip, has(80) ? 80 : 8080));
    if (has(23) || has(2323)) results.push(await this.deps.checkLineService(device.ip, has(23) ? 23 : 2323, "telnet"));
    if (has(21)) results.push(await this.deps.checkLineService(device.ip, 21, "ftp"));
    if (!results.length) throw new IpcError("unavailable", "This device has no login service (web page, Telnet or FTP) to check.");
    return { ip: device.ip, results };
  }
}

