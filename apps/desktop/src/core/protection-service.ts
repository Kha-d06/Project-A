/**
 * Real-time protection for any interface over qalaa-ipc, run by the background
 * service itself (until now these engines ran only inside the Electron window):
 *
 * - New-file watching: each new file in the watched folders is scanned once it
 *   stops changing; a known threat is quarantined when auto-quarantine is on.
 * - Ransomware watch over the protected folders, with hidden decoy files that
 *   nothing should touch. A decoy changed while Qalaa was stopped is reported
 *   at start.
 * - On-access scanning (Linux, fanotify): a root helper asks this service for a
 *   verdict before a file opens. The same feed spots a program rewriting many
 *   protected files at once and freezes it until the person decides.
 * - Windows Controlled Folder Access, terminal protection (Linux and macOS),
 *   the Wi-Fi check and pending OS updates.
 *
 * Every engine is unchanged; this service only owns their lifecycle and state.
 * Anything that needs root or administrator rights asks the system for it
 * (pkexec or a UAC prompt); nothing is elevated silently.
 */
import { homedir, userInfo } from "node:os";
import { isAbsolute } from "node:path";

import type { CfaState, CfaStatus } from "../engine/cfa";
import type { DecoyRecord } from "../engine/protection";
import type { RansomwareAlert } from "../engine/ransomware";
import type { TerminalSetup } from "../engine/shell-init";
import type { PendingUpdate, WifiStatus } from "../engine/system";
import type { ScanResult } from "../engine/types";
import { IpcError } from "./protocol";

export type OnAccessState = "active" | "inactive" | "failed" | "absent";

export interface HaltedProcess {
  pid: number;
  reason: string;
  files: number;
  at: string;
}

export interface ProtectionSettings {
  watchEnabled: boolean;
  watchFolders: string[];
  ransomwareWatch: boolean;
  ransomwareDecoys: boolean;
  protectedFolders: string[];
  onAccessScan: boolean;
}

export interface ProtectionStatus {
  platform: NodeJS.Platform;
  realtime: { on: boolean; folders: string[] };
  ransomware: { on: boolean; decoys: boolean; decoyCount: number; folders: string[]; lastAlert: (RansomwareAlert & { at: string }) | null; halted: HaltedProcess[] };
  onAccess: { supported: boolean; on: boolean; state: OnAccessState; manageable: boolean; responder: boolean };
  cfa: { supported: boolean; state: CfaState; folders: string[]; allowedApps: string[] } | null;
  terminal: { supported: boolean; command: string | null; shells: { shell: string; enabled: boolean }[] };
}

export interface SystemChecks {
  wifi: WifiStatus | null;
  updates: { count: number; source: string; items: PendingUpdate[] } | null;
  checkedAt: string;
}

/** What the engines look like to this service (real ones in daemon.ts, fakes in tests). */
export interface ProtectionDeps {
  platform: NodeJS.Platform;
  settings: () => ProtectionSettings;
  saveSettings: (changes: Partial<ProtectionSettings>) => Promise<void>;
  /** Scans and records a file found by a watcher (ScanService.scanAutomatic). */
  scanAutomatic: (path: string, known?: ScanResult) => Promise<unknown>;
  /** Scans without recording (on-access verdicts are recorded only when blocked). */
  scanFile: (path: string) => Promise<ScanResult>;
  isExcluded: (path: string) => boolean;
  emit: (event: "alert" | "threat.blocked", payload: unknown) => void;
  folderWatcher: { set(folders: string[]): void };
  ransomwareMonitor: { set(folders: string[]): void; setDecoys(record: DecoyRecord): void };
  decoys: {
    load(): Promise<DecoyRecord>;
    save(record: DecoyRecord): Promise<void>;
    plant(folders: string[]): Promise<DecoyRecord>;
    tampered(record: DecoyRecord): Promise<{ path: string; state: "changed" | "missing" }[]>;
    remove(path: string): Promise<void>;
  };
  onAccess: {
    supported: boolean;
    status(): Promise<{ state: OnAccessState; manageable: boolean }>;
    enable(): Promise<void>;
    disable(): Promise<void>;
    /** Starts the local responder the root helper asks; returns a stopper. */
    startResponder(hooks: {
      scan: (path: string) => Promise<ScanResult>;
      isExcluded: (path: string) => boolean;
      onBlocked: (path: string, result: ScanResult) => void;
      onHalt: (pid: number, reason: string, files: number) => void;
      onOpen: (pid: number, path: string) => void;
      feed: (pid: number, path: string) => { reason: string; files: number } | null;
    }): Promise<{ stop(): Promise<void> } | null>;
    burst: { feed(event: { pid: number; path: string; at: number }): { reason: string; files: number } | null; clear(pid: number): void };
    /** Resumes (SIGCONT) or removes (SIGKILL) a frozen process; the helper froze it as root. */
    signal(pid: number, action: "resume" | "kill"): Promise<void>;
  };
  /** Credential guardrails see every open the on-access helper reports. */
  observeOpen?: (pid: number, path: string) => void;
  cfa: { status(): Promise<CfaStatus>; apply(action: "enable" | "disable" | "audit" | "add-folder" | "allow-app", path?: string): Promise<void> };
  terminal: { status(): Promise<TerminalSetup>; enable(): Promise<{ changed: string[]; setup: TerminalSetup }>; disable(): Promise<{ changed: string[]; setup: TerminalSetup }> };
  /** Called with files Qalaa itself edited (shell profiles), so integrity checks accept them. */
  acceptChanged?: (files: string[]) => Promise<void>;
  wifi: () => Promise<WifiStatus>;
  updates: () => Promise<{ updates: PendingUpdate[]; source: string } | null>;
  now?: () => number;
}

const CFA_ACTIONS = ["enable", "disable", "audit", "add-folder", "allow-app"] as const;

function boolParam(params: unknown, key = "on"): boolean {
  const value = (params as Record<string, unknown> | undefined)?.[key];
  if (typeof value !== "boolean") throw new IpcError("bad_params", `"${key}" must be true or false.`);
  return value;
}

function failed(error: unknown): IpcError {
  return error instanceof IpcError ? error : new IpcError("failed", (error instanceof Error ? error.message : String(error)).slice(0, 300));
}

export class ProtectionService {
  private decoys: DecoyRecord = {};
  private decoyKey = "";
  private lastAlert: (RansomwareAlert & { at: string }) | null = null;
  private readonly halted = new Map<number, Omit<HaltedProcess, "pid">>();
  private responder: { stop(): Promise<void> } | null = null;
  private readonly now: () => number;

  constructor(private readonly deps: ProtectionDeps) {
    this.now = deps.now ?? Date.now;
  }

  /** At start: report decoys changed while stopped, then start what the settings ask for. */
  async start(): Promise<void> {
    this.decoys = await this.deps.decoys.load().catch(() => ({}));
    const tampered = await this.deps.decoys.tampered(this.decoys).catch(() => []);
    if (tampered.length) {
      this.ransomwareAlert({
        reasons: [`${tampered.length} hidden decoy file(s) were changed or deleted while Qalaa was not running`],
        examples: tampered.map((t) => t.path).slice(0, 5),
      });
    }
    await this.apply(true);
    if (this.deps.settings().onAccessScan) await this.startResponder();
  }

  async stop(): Promise<void> {
    this.deps.folderWatcher.set([]);
    this.deps.ransomwareMonitor.set([]);
    await this.responder?.stop().catch(() => undefined);
    this.responder = null;
  }

  /** Called by the RansomwareMonitor (and at start for tampered decoys). */
  ransomwareAlert(alert: RansomwareAlert): void {
    this.lastAlert = { ...alert, at: new Date(this.now()).toISOString() };
    this.deps.emit("alert", { kind: "ransomware", reasons: alert.reasons });
  }

  /** Called by the FolderWatcher for each settled new file. */
  onNewFile(path: string): void {
    if (this.deps.isExcluded(path)) return;
    void this.deps.scanAutomatic(path).catch(() => undefined);
  }

  /** Re-applies the watchers after a settings change (Home toggles go through here too). */
  async apply(forceDecoys = false): Promise<void> {
    const s = this.deps.settings();
    this.deps.folderWatcher.set(s.watchEnabled ? s.watchFolders : []);
    this.deps.ransomwareMonitor.set(s.ransomwareWatch ? s.protectedFolders : []);
    const wanted = s.ransomwareWatch && s.ransomwareDecoys ? s.protectedFolders : [];
    const key = JSON.stringify(wanted);
    if (!forceDecoys && key === this.decoyKey) return;
    this.decoyKey = key;
    this.deps.ransomwareMonitor.setDecoys({});
    for (const path of Object.keys(this.decoys)) await this.deps.decoys.remove(path).catch(() => undefined);
    this.decoys = wanted.length ? await this.deps.decoys.plant(wanted).catch(() => ({})) : {};
    await this.deps.decoys.save(this.decoys).catch(() => undefined);
    this.deps.ransomwareMonitor.setDecoys(this.decoys);
  }

  async status(): Promise<ProtectionStatus> {
    const s = this.deps.settings();
    const onAccess = this.deps.onAccess.supported ? await this.deps.onAccess.status().catch(() => ({ state: "absent" as const, manageable: false })) : { state: "absent" as const, manageable: false };
    const cfa = this.deps.platform === "win32" ? await this.deps.cfa.status().catch(() => null) : null;
    const terminalSupported = this.deps.platform !== "win32";
    const terminal = terminalSupported ? await this.deps.terminal.status().catch(() => null) : null;
    return {
      platform: this.deps.platform,
      realtime: { on: s.watchEnabled, folders: s.watchFolders },
      ransomware: {
        on: s.ransomwareWatch,
        decoys: s.ransomwareDecoys,
        decoyCount: Object.keys(this.decoys).length,
        folders: s.protectedFolders,
        lastAlert: this.lastAlert,
        halted: [...this.halted.entries()].map(([pid, info]) => ({ pid, ...info })),
      },
      onAccess: { supported: this.deps.onAccess.supported, on: s.onAccessScan, state: onAccess.state, manageable: onAccess.manageable, responder: this.responder !== null },
      cfa: cfa ? { supported: cfa.supported, state: cfa.state, folders: cfa.folders, allowedApps: cfa.allowedApps } : null,
      terminal: { supported: terminalSupported, command: terminal?.command ?? null, shells: (terminal?.shells ?? []).map((sh) => ({ shell: sh.shell, enabled: sh.enabled })) },
    };
  }

  async setRealtime(params: unknown): Promise<ProtectionStatus> {
    await this.deps.saveSettings({ watchEnabled: boolParam(params) });
    await this.apply();
    return this.status();
  }

  async setRansomware(params: unknown): Promise<ProtectionStatus> {
    await this.deps.saveSettings({ ransomwareWatch: boolParam(params) });
    await this.apply();
    return this.status();
  }

  async setDecoys(params: unknown): Promise<ProtectionStatus> {
    await this.deps.saveSettings({ ransomwareDecoys: boolParam(params) });
    await this.apply();
    return this.status();
  }

  async addFolder(params: unknown): Promise<ProtectionStatus> {
    const path = this.folderParam(params);
    const s = this.deps.settings();
    if (!s.protectedFolders.includes(path)) await this.deps.saveSettings({ protectedFolders: [...s.protectedFolders, path].slice(0, 50) });
    await this.apply();
    return this.status();
  }

  async removeFolder(params: unknown): Promise<ProtectionStatus> {
    const path = this.folderParam(params);
    await this.deps.saveSettings({ protectedFolders: this.deps.settings().protectedFolders.filter((f) => f !== path) });
    await this.apply();
    return this.status();
  }

  /** Installs or removes the root helper (a pkexec prompt) and starts or stops the responder. */
  async setOnAccess(params: unknown): Promise<ProtectionStatus> {
    const on = boolParam(params);
    if (!this.deps.onAccess.supported) throw new IpcError("unavailable", "On-access scanning is available on Linux only.");
    try {
      if (on) {
        await this.startResponder();
        await this.deps.onAccess.enable();
      } else {
        await this.deps.onAccess.disable();
        await this.responder?.stop().catch(() => undefined);
        this.responder = null;
      }
    } catch (error) {
      if (on) {
        await this.responder?.stop().catch(() => undefined);
        this.responder = null;
      }
      throw failed(error);
    }
    await this.deps.saveSettings({ onAccessScan: on });
    return this.status();
  }

  /** Resume or remove a process frozen for ransomware behaviour. */
  async resolveHalted(params: unknown): Promise<ProtectionStatus> {
    const { pid, action } = (params ?? {}) as { pid?: unknown; action?: unknown };
    if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 1) throw new IpcError("bad_params", "Expected a process id.");
    if (action !== "resume" && action !== "kill") throw new IpcError("bad_params", 'Expected "resume" or "kill".');
    if (!this.halted.has(pid)) throw new IpcError("not_found", "That process is no longer frozen.");
    await this.deps.onAccess.signal(pid, action).catch((error: unknown) => {
      throw failed(error);
    });
    this.halted.delete(pid);
    this.deps.onAccess.burst.clear(pid);
    return this.status();
  }

  async cfaApply(params: unknown): Promise<ProtectionStatus> {
    if (this.deps.platform !== "win32") throw new IpcError("unavailable", "Controlled Folder Access is a Windows feature.");
    const { action, path } = (params ?? {}) as { action?: unknown; path?: unknown };
    if (!CFA_ACTIONS.includes(action as (typeof CFA_ACTIONS)[number])) throw new IpcError("bad_params", "Unknown Controlled Folder Access action.");
    if ((action === "add-folder" || action === "allow-app") && (typeof path !== "string" || !/^[a-z]:[\\/]|^\\\\/i.test(path))) {
      throw new IpcError("bad_params", "Use a full Windows path.");
    }
    await this.deps.cfa.apply(action as (typeof CFA_ACTIONS)[number], typeof path === "string" ? path : undefined).catch((error: unknown) => {
      throw failed(error);
    });
    return this.status();
  }

  async setTerminal(params: unknown): Promise<ProtectionStatus> {
    const on = boolParam(params);
    if (this.deps.platform === "win32") throw new IpcError("unavailable", "Terminal protection is for Linux and macOS.");
    const result = await (on ? this.deps.terminal.enable() : this.deps.terminal.disable()).catch((error: unknown) => {
      throw failed(error);
    });
    // Qalaa's own edit to ~/.bashrc / ~/.zshrc is expected: no integrity alarm for it.
    if (result.changed.length) await this.deps.acceptChanged?.(result.changed).catch(() => undefined);
    return this.status();
  }

  /** Slower checks, run when the page asks: the Wi-Fi network and pending OS updates. */
  async system(): Promise<SystemChecks> {
    const [wifi, updates] = await Promise.all([this.deps.wifi().catch(() => null), this.deps.updates().catch(() => null)]);
    return {
      wifi,
      updates: updates ? { count: updates.updates.length, source: updates.source, items: updates.updates.slice(0, 50) } : null,
      checkedAt: new Date(this.now()).toISOString(),
    };
  }

  private folderParam(params: unknown): string {
    const path = (params as { path?: unknown } | undefined)?.path;
    const absolute = typeof path === "string" && (this.deps.platform === "win32" ? /^[a-z]:[\\/]|^\\\\/i.test(path) : isAbsolute(path));
    if (!absolute || (path as string).length > 1024) throw new IpcError("bad_params", "Use the full path of a folder.");
    return (path as string).trim();
  }

  private async startResponder(): Promise<void> {
    if (this.responder || !this.deps.onAccess.supported) return;
    const roots = () => this.deps.settings().protectedFolders;
    const under = (path: string) => roots().some((root) => path === root || path.startsWith(root.endsWith("/") ? root : `${root}/`));
    this.responder = await this.deps.onAccess
      .startResponder({
        scan: (path) => this.deps.scanFile(path),
        isExcluded: (path) => this.deps.isExcluded(path),
        onBlocked: (path, result) => void this.deps.scanAutomatic(path, result).catch(() => undefined),
        onOpen: (pid, path) => this.deps.observeOpen?.(pid, path),
        feed: (pid, path) => (this.deps.settings().ransomwareWatch && under(path) ? this.deps.onAccess.burst.feed({ pid, path, at: this.now() }) : null),
        onHalt: (pid, reason, files) => {
          this.halted.set(pid, { reason, files, at: new Date(this.now()).toISOString() });
          this.deps.emit("alert", { kind: "ransomware", halted: pid, reason });
        },
      })
      .catch(() => null);
  }
}

/** The person running the service and their home, for the on-access helper. */
export function onAccessIdentity(): { user: string; home: string } {
  return { user: userInfo().username, home: homedir() };
}
