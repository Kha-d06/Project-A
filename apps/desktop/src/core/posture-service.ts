/**
 * Security posture for any interface over qalaa-ipc (until now only inside the
 * Electron window). Engines unchanged:
 *
 * - The posture score (engine/posture.ts): firewall, disk encryption (LUKS,
 *   ZFS and fscrypt; BitLocker and Device Encryption; FileVault), TPM 1.2/2.0,
 *   UEFI Secure Boot, pending OS updates, exposed risky ports, suspicious startup
 *   entries, and the platform's own checks (Defender, UAC, SSH and so on).
 *   A check that couldn't run is "unknown", and unknown checks don't count
 *   towards the score in either direction.
 * - Startup programs, with what's new since the person last reviewed them, and
 *   switching an entry off (or back on) where that needs no administrator.
 * - File integrity: the hosts file, authorized_keys, shell profiles and the
 *   like, hashed and watched; a change is an alert until it's accepted. The
 *   monitor now runs in the background service.
 * - USB keyboards (BadUSB): the count of new ones, from the keyboard service.
 */
import { isAbsolute } from "node:path";

import type { Change, IntegrityStore } from "../engine/integrity";
import type { Posture } from "../engine/posture";
import type { EncryptionStatus } from "../engine/encryption";
import type { FirewallStatus, ListeningPort, StartupItem } from "../engine/security";
import type { DisabledStartup } from "../engine/tools";
import { IpcError } from "./protocol";

export interface StartupRow extends StartupItem {
  isNew: boolean;
  canSwitchOff: boolean;
}

export interface PostureStatus {
  posture: Posture | null;
  firewall: FirewallStatus | null;
  encryption: EncryptionStatus | null;
  startup: StartupRow[];
  disabledStartup: DisabledStartup[];
  /** True until the first check sets the startup baseline. */
  startupBaselineSet: boolean;
  integrity: IntegrityStore;
  usb: { newKeyboards: number };
  checking: boolean;
}

export interface PostureDeps {
  platform: NodeJS.Platform;
  posture: (facts: { firewall: FirewallStatus["state"]; encryption: EncryptionStatus["state"]; pendingUpdates: number | null; riskyPorts: number | null; suspiciousStartup: number }) => Promise<Posture>;
  firewall: () => Promise<FirewallStatus>;
  encryption: () => Promise<EncryptionStatus>;
  pendingUpdates: () => Promise<number | null>;
  ports: () => Promise<ListeningPort[] | null>;
  startup: () => Promise<StartupItem[]>;
  canSwitchOff: (item: StartupItem) => boolean;
  switchOff: (item: StartupItem) => Promise<DisabledStartup>;
  switchOn: (entry: DisabledStartup) => Promise<void>;
  knownStartup: () => string[];
  saveKnownStartup: (ids: string[]) => Promise<void>;
  loadDisabled: () => Promise<DisabledStartup[]>;
  saveDisabled: (entries: DisabledStartup[]) => Promise<void>;
  integrity: {
    state: IntegrityStore;
    check(): Promise<Change[]>;
    accept(path: string): Promise<IntegrityStore>;
    setPaths(paths: string[]): Promise<IntegrityStore>;
    rebaseline(): Promise<IntegrityStore>;
  };
  newKeyboards: () => number;
}

function pathParam(params: unknown, key = "path"): string {
  const value = (params as Record<string, unknown> | undefined)?.[key];
  if (typeof value !== "string" || !value.trim() || value.length > 4096) throw new IpcError("bad_params", "Expected a path.");
  return value.trim();
}

export class PostureService {
  private last: Posture | null = null;
  private firewall: FirewallStatus | null = null;
  private encryption: EncryptionStatus | null = null;
  private startupItems: StartupItem[] = [];
  private disabled: DisabledStartup[] = [];
  private checking: Promise<PostureStatus> | null = null;

  constructor(private readonly deps: PostureDeps) {}

  async load(): Promise<void> {
    this.disabled = await this.deps.loadDisabled().catch(() => []);
  }

  status(): PostureStatus {
    const known = new Set(this.deps.knownStartup());
    return {
      posture: this.last,
      firewall: this.firewall,
      encryption: this.encryption,
      startup: this.startupItems.map((item) => ({ ...item, isNew: known.size > 0 && !known.has(item.id), canSwitchOff: this.deps.canSwitchOff(item) })),
      disabledStartup: this.disabled,
      startupBaselineSet: known.size > 0,
      integrity: this.deps.integrity.state,
      usb: { newKeyboards: this.deps.newKeyboards() },
      checking: this.checking !== null,
    };
  }

  /** Runs every check (a few seconds; concurrent callers share one run). */
  check(): Promise<PostureStatus> {
    this.checking ??= this.runCheck().finally(() => {
      this.checking = null;
    });
    return this.checking;
  }

  private async runCheck(): Promise<PostureStatus> {
    const [firewall, encryption, updates, ports, startup] = await Promise.all([
      this.deps.firewall().catch((): FirewallStatus => ({ state: "unknown", detail: null, source: null })),
      this.deps.encryption().catch((): EncryptionStatus => ({ state: "unknown", detail: null, source: null })),
      this.deps.pendingUpdates().catch(() => null),
      this.deps.ports().catch(() => null),
      this.deps.startup().catch(() => []),
    ]);
    this.firewall = firewall;
    this.encryption = encryption;
    this.startupItems = startup;
    // The first check sets the baseline; later checks point out what's new since.
    if (this.deps.knownStartup().length === 0 && startup.length) await this.deps.saveKnownStartup(startup.map((s) => s.id).slice(0, 2000));
    this.last = await this.deps.posture({
      firewall: firewall.state,
      encryption: encryption.state,
      pendingUpdates: updates,
      riskyPorts: ports ? ports.filter((p) => p.exposed && p.risk).length : null,
      suspiciousStartup: startup.filter((s) => s.warnings.length).length,
    });
    await this.deps.integrity.check().catch(() => []);
    return this.status();
  }

  /** "I've looked at these": the current startup entries become the known list. */
  async acknowledgeStartup(): Promise<PostureStatus> {
    await this.deps.saveKnownStartup(this.startupItems.map((s) => s.id).slice(0, 2000));
    return this.status();
  }

  async startupOff(params: unknown): Promise<PostureStatus> {
    const id = pathParam(params, "id");
    const item = this.startupItems.find((s) => s.id === id);
    if (!item) throw new IpcError("not_found", "That entry is no longer listed. Check again.");
    if (!this.deps.canSwitchOff(item)) throw new IpcError("not_allowed", "This entry can only be changed with administrator tools.");
    const entry = await this.deps.switchOff(item).catch((error: unknown) => {
      throw new IpcError("failed", error instanceof Error ? error.message : String(error));
    });
    this.disabled = [entry, ...this.disabled.filter((d) => d.id !== entry.id)];
    await this.deps.saveDisabled(this.disabled);
    this.startupItems = this.startupItems.filter((s) => s.id !== id);
    return this.status();
  }

  async startupOn(params: unknown): Promise<PostureStatus> {
    const id = pathParam(params, "id");
    const entry = this.disabled.find((d) => d.id === id);
    if (!entry) throw new IpcError("not_found", "That entry isn't in the switched-off list.");
    await this.deps.switchOn(entry).catch((error: unknown) => {
      throw new IpcError("failed", error instanceof Error ? error.message : String(error));
    });
    this.disabled = this.disabled.filter((d) => d.id !== id);
    await this.deps.saveDisabled(this.disabled);
    this.startupItems = await this.deps.startup().catch(() => this.startupItems);
    return this.status();
  }

  async integrityCheck(): Promise<PostureStatus> {
    await this.deps.integrity.check();
    return this.status();
  }

  async integrityAccept(params: unknown): Promise<PostureStatus> {
    const path = pathParam(params);
    if (!this.deps.integrity.state.changes.some((c) => c.path === path)) throw new IpcError("not_found", "There's no change to accept for that file.");
    await this.deps.integrity.accept(path);
    return this.status();
  }

  async integrityAdd(params: unknown): Promise<PostureStatus> {
    const path = pathParam(params);
    const absolute = this.deps.platform === "win32" ? /^[a-z]:[\\/]|^\\\\/i.test(path) : isAbsolute(path);
    if (!absolute) throw new IpcError("bad_params", "Use the full path of a file.");
    await this.deps.integrity.setPaths([...this.deps.integrity.state.paths, path]);
    return this.status();
  }

  async integrityRemove(params: unknown): Promise<PostureStatus> {
    const path = pathParam(params);
    await this.deps.integrity.setPaths(this.deps.integrity.state.paths.filter((p) => p !== path));
    return this.status();
  }

  /** Everything as it is now becomes the expected state. */
  async integrityReset(): Promise<PostureStatus> {
    await this.deps.integrity.rebaseline();
    return this.status();
  }
}
