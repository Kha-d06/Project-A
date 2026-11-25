/**
 * Credential guardrails as a service, shared by the background service and the
 * classic app. Watches who opens SSH keys, .env files, cloud credentials and
 * browser secret stores; when a program that isn't expected to opens one, it
 * raises a high-priority `alert` with three answers: Suspend (pause the program
 * so nothing more is read or sent), Terminate, or Allow this program.
 *
 * Sources, by platform:
 * - Linux: every open from the fanotify on-access helper, when it is installed
 *   (`observe` is called for each), plus a look at /proc every few seconds;
 * - macOS: `lsof` for the person's own processes every 15 seconds;
 * - Windows: not available yet. Seeing which program has a file open needs
 *   a system handle query from native code, which isn't built.
 * Polling catches files a program keeps open; a quick read between two looks
 * can be missed, and the status says which mode is running.
 *
 * Only the kind of file, a shortened path and the program are kept. File
 * contents are never read.
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";

import {
  type CredentialKind,
  HIGH_SEVERITY,
  type OpenFile,
  type TrustedProgram,
  credentialKind,
  displayPath,
  exeOf,
  keychainDumps,
  nameAllowed,
  parseLsof,
  parsePsComm,
  procOpenFiles,
  programName,
} from "../engine/credentials";
import { sha256File, trustedLocationFor } from "../engine/program-trust";
import { atomicWrite } from "./atomic-write";
import type { Emit } from "./handlers";
import { IpcError } from "./protocol";

export type GuardMode = "every_open" | "polling" | "unavailable";

export interface CredentialIncident {
  id: string;
  pid: number;
  program: string;
  exe: string;
  credential: CredentialKind;
  /** "~/.ssh/id_ed25519": the home folder is never shown in full. */
  file: string;
  at: string;
  state: "open" | "suspended" | "terminated";
  severity: "warning" | "high";
  /** Set when the opens together look like a known stealer pattern. */
  pattern?: "browser_key_and_secrets";
}

/** A command seen running that reads credentials without opening a file we watch (macOS `security dump-keychain`). */
export interface CredentialCommand {
  pid: number;
  exe: string;
  command: string;
  kind: CredentialKind;
}

export interface CredentialStatus {
  supported: boolean;
  enabled: boolean;
  mode: GuardMode;
  /** Newest first; open and suspended ones wait for a decision. */
  incidents: CredentialIncident[];
  trusted: string[];
  lastPoll: PollInfo | null;
}

export type Signal = "SIGSTOP" | "SIGCONT" | "SIGKILL";

export interface CredentialGuardDeps {
  file: string;
  home: string;
  platform: NodeJS.Platform;
  emit: Emit;
  /** Open files of the person's processes; null where it can't be listed. */
  source?: () => Promise<OpenFile[] | null>;
  /** The executable a pid runs now (guards against a reused pid); null if unknown. */
  exeOf?: (pid: number) => Promise<string | null>;
  signal?: (pid: number, signal: Signal) => void;
  /** Credential-reading commands running now (macOS keychain dumps). */
  commands?: () => Promise<CredentialCommand[]>;
  /** Where only the system or an administrator could have put the program. */
  trustedLocation?: (exe: string) => Promise<boolean>;
  hashFile?: (exe: string) => Promise<string | null>;
  now?: () => number;
  selfPid?: number;
}

const MAX_INCIDENTS = 20;
const MAX_SEEN = 2_000;

export interface PollInfo {
  at: string;
  ms: number;
  files: number;
  commands: number;
  error?: string;
}

export function pollMs(platform: NodeJS.Platform): number {
  return platform === "darwin" ? 15_000 : 5_000;
}

const LOCATION_CACHE_MS = 10 * 60 * 1000;

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10_000, maxBuffer: 16 * 1024 * 1024 }, (error, stdout) => (error && !stdout ? reject(error) : resolve(String(stdout))));
  });
}

/** The platform's default "who has what open" source, or null where there is none. */
export function defaultSource(platform: NodeJS.Platform, home: string): CredentialGuardDeps["source"] | undefined {
  const interesting = (path: string) => credentialKind(path, home) !== null;
  if (platform === "linux") return () => procOpenFiles(interesting);
  if (platform === "darwin") {
    return async () => {
      // lsof exits 1 when some files can't be listed but still prints the rest.
      const opened = parseLsof(await run("lsof", ["-u", userInfo().username, "-Fpn", "-n", "-P"]).catch(() => "")).filter((f) => interesting(f.path));
      if (!opened.length) return [];
      // lsof cuts command names short; ps gives the full executable path.
      const pids = [...new Set(opened.map((f) => f.pid))];
      const exes = parsePsComm(await run("ps", ["-o", "pid=,comm=", "-p", pids.join(",")]).catch(() => ""));
      return opened.map((f) => ({ ...f, exe: exes.get(f.pid) ?? "unknown" }));
    };
  }
  return undefined;
}

export function defaultCommands(platform: NodeJS.Platform): CredentialGuardDeps["commands"] | undefined {
  if (platform !== "darwin") return undefined;
  return async () =>
    keychainDumps(await run("ps", ["-axww", "-o", "pid=,command="])).map((d) => ({ pid: d.pid, exe: "/usr/bin/security", command: d.command, kind: "keychain" as const }));
}

export function defaultExeOf(platform: NodeJS.Platform): (pid: number) => Promise<string | null> {
  if (platform === "darwin") return async (pid) => (await run("ps", ["-p", String(pid), "-o", "comm="]).catch(() => "")).trim() || null;
  return (pid) => exeOf(pid, platform);
}

export class CredentialGuardService {
  private trusted: TrustedProgram[] = [];
  private locations = new Map<string, { trusted: boolean; until: number }>();
  /** What each suspicious process has opened recently, to spot stealer patterns. */
  private kindsByPid = new Map<number, Set<CredentialKind>>();
  private incidents: CredentialIncident[] = [];
  private seen = new Set<string>();
  private enabled = true;
  private everyOpen = false;
  private counter = 0;
  private readonly source: CredentialGuardDeps["source"];
  private readonly commands: CredentialGuardDeps["commands"];
  private readonly trustedLocation: (exe: string) => Promise<boolean>;
  private readonly hashFile: (exe: string) => Promise<string | null>;
  private readonly exeOf: (pid: number) => Promise<string | null>;
  private readonly signal: (pid: number, signal: Signal) => void;
  private readonly now: () => number;
  private readonly selfPid: number;

  constructor(private readonly deps: CredentialGuardDeps) {
    this.source = deps.source ?? defaultSource(deps.platform, deps.home);
    this.commands = deps.commands ?? defaultCommands(deps.platform);
    this.trustedLocation = deps.trustedLocation ?? trustedLocationFor(deps.platform);
    this.hashFile = deps.hashFile ?? sha256File;
    this.exeOf = deps.exeOf ?? defaultExeOf(deps.platform);
    this.signal = deps.signal ?? ((pid, sig) => process.kill(pid, sig));
    this.now = deps.now ?? Date.now;
    this.selfPid = deps.selfPid ?? process.pid;
  }

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.deps.file, "utf8")) as { trusted?: unknown };
      const list = Array.isArray(saved.trusted) ? saved.trusted : [];
      // Older files listed paths only; their hash is pinned the next time the program is seen.
      this.trusted = list
        .map((t): TrustedProgram | null =>
          typeof t === "string"
            ? { exe: t, sha256: null }
            : t && typeof t === "object" && typeof (t as TrustedProgram).exe === "string"
              ? { exe: (t as TrustedProgram).exe, sha256: typeof (t as TrustedProgram).sha256 === "string" ? (t as TrustedProgram).sha256 : null }
              : null,
        )
        .filter((t): t is TrustedProgram => t !== null)
        .slice(0, 200);
    } catch {
      this.trusted = [];
    }
  }

  private save(): Promise<void> {
    return atomicWrite(this.deps.file, JSON.stringify({ trusted: this.trusted }));
  }

  isSupported(): boolean {
    return this.source !== undefined;
  }

  configure(options: { enabled?: boolean; everyOpen?: boolean }): void {
    if (options.enabled !== undefined) this.enabled = options.enabled;
    if (options.everyOpen !== undefined) this.everyOpen = options.everyOpen && this.deps.platform === "linux";
  }

  mode(): GuardMode {
    if (!this.isSupported()) return "unavailable";
    return this.everyOpen ? "every_open" : "polling";
  }

  /** Open incidents, for the Home model. */
  pendingCount(): number {
    return this.incidents.filter((i) => i.state !== "terminated").length;
  }

  status(): CredentialStatus {
    return { supported: this.isSupported(), enabled: this.enabled, mode: this.mode(), incidents: this.incidents.map((i) => ({ ...i })), trusted: this.trusted.map((t) => t.exe), lastPoll: this.lastPoll() };
  }

  /** Expected: allowed by the person (same path and binary), or a default name in a trusted location. */
  private async allowed(kind: CredentialKind, exe: string): Promise<boolean> {
    const pinned = this.trusted.find((t) => t.exe === exe);
    if (pinned) {
      const hash = await this.hashFile(exe);
      if (hash && pinned.sha256 === null) {
        pinned.sha256 = hash;
        await this.save();
        return true;
      }
      if (hash && hash === pinned.sha256) return true;
      // Changed or unreadable binary at an allowed path: report it again.
    }
    if (!nameAllowed(kind, exe)) return false;
    const now = this.now();
    const cached = this.locations.get(exe);
    if (cached && cached.until > now) return cached.trusted;
    const trusted = await this.trustedLocation(exe);
    this.locations.set(exe, { trusted, until: now + LOCATION_CACHE_MS });
    return trusted;
  }

  /** One open of `path` by `pid`. Cheap for every other file: the path is classified first. */
  async observe(pid: number, path: string, exe?: string): Promise<CredentialIncident | null> {
    if (!this.enabled || pid === this.selfPid || pid <= 0) return null;
    const credential = credentialKind(path, this.deps.home);
    if (!credential) return null;
    const seenKey = `${pid}\0${path}`;
    if (this.seen.has(seenKey)) return null;
    const program = exe ?? (await this.exeOf(pid)) ?? "unknown";
    if (await this.allowed(credential, program)) return null;
    this.remember(seenKey);
    return this.raise(pid, program, credential, displayPath(path, this.deps.home));
  }

  /** A command line that reads credentials (macOS `security dump-keychain`). */
  async observeCommand(command: CredentialCommand): Promise<CredentialIncident | null> {
    if (!this.enabled || command.pid === this.selfPid || command.pid <= 0) return null;
    const seenKey = `${command.pid}\0cmd:${command.command}`;
    if (this.seen.has(seenKey)) return null;
    this.remember(seenKey);
    return this.raise(command.pid, command.exe, command.kind, command.command);
  }

  private raise(pid: number, program: string, credential: CredentialKind, file: string): CredentialIncident {
    const kinds = this.kindsByPid.get(pid) ?? new Set<CredentialKind>();
    kinds.add(credential);
    this.kindsByPid.set(pid, kinds);
    if (this.kindsByPid.size > 500) this.kindsByPid.delete(this.kindsByPid.keys().next().value!);
    // Reading a browser's decryption key and its passwords or cookies is what stealers do.
    const stealer = kinds.has("browser_key") && kinds.has("browser_secrets");
    const severity = stealer || HIGH_SEVERITY.has(credential) ? "high" : "warning";
    const incident: CredentialIncident = {
      id: `c${this.now().toString(36)}${(this.counter++).toString(36)}`,
      pid,
      program: programName(program),
      exe: program,
      credential,
      file,
      at: new Date(this.now()).toISOString(),
      state: "open",
      severity,
      ...(stealer ? { pattern: "browser_key_and_secrets" as const } : {}),
    };
    this.incidents = [incident, ...this.incidents].slice(0, MAX_INCIDENTS);
    this.deps.emit("alert", {
      kind: "credential",
      id: incident.id,
      pid,
      program: incident.program,
      credential,
      file,
      severity,
      ...(incident.pattern ? { pattern: incident.pattern } : {}),
    });
    return incident;
  }

  private inFlight: Promise<CredentialIncident[]> | null = null;
  private last: PollInfo | null = null;

  /** One look at what is open now; returns new incidents. Overlapping calls share one look. */
  poll(): Promise<CredentialIncident[]> {
    this.inFlight ??= this.look().finally(() => (this.inFlight = null));
    return this.inFlight;
  }

  /** When the last look ran and what it saw, for diagnostics. */
  lastPoll(): PollInfo | null {
    return this.last ? { ...this.last } : null;
  }

  private async look(): Promise<CredentialIncident[]> {
    if (!this.enabled || !this.source) return [];
    const started = this.now();
    const found: CredentialIncident[] = [];
    const errors: string[] = [];
    // Commands first: one ps is quick, while lsof on a busy Mac can take many seconds.
    const commands = (await this.commands?.().catch((e: unknown) => (errors.push(`commands: ${String(e)}`), []))) ?? [];
    for (const c of commands) {
      const incident = await this.observeCommand(c);
      if (incident) found.push(incident);
    }
    const files = (await this.source().catch((e: unknown) => (errors.push(`files: ${String(e)}`), []))) ?? [];
    for (const f of files) {
      const incident = await this.observe(f.pid, f.path, f.exe);
      if (incident) found.push(incident);
    }
    this.last = { at: new Date(started).toISOString(), ms: this.now() - started, files: files.length, commands: commands.length, ...(errors.length ? { error: errors.join("; ").slice(0, 300) } : {}) };
    return found;
  }

  private remember(key: string): void {
    if (this.seen.size >= MAX_SEEN) this.seen = new Set([...this.seen].slice(MAX_SEEN / 2));
    this.seen.add(key);
  }

  private find(id: unknown): CredentialIncident {
    if (typeof id !== "string" || id.length > 64) throw new IpcError("bad_params", "Expected an incident id.");
    const incident = this.incidents.find((i) => i.id === id);
    if (!incident) throw new IpcError("not_found", "That alert is no longer listed.");
    return incident;
  }

  /** Signals the process only if the same program still runs under that pid. */
  private async send(incident: CredentialIncident, signal: Signal): Promise<void> {
    if (this.deps.platform === "win32") throw new IpcError("unavailable", "Pausing or stopping programs from Qalaa isn't available on Windows yet.");
    const current = await this.exeOf(incident.pid);
    if (!current || programName(current) !== incident.program) throw new IpcError("not_found", "That program has already closed.");
    try {
      this.signal(incident.pid, signal);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ESRCH") throw new IpcError("not_found", "That program has already closed.");
      if (code === "EPERM") throw new IpcError("not_allowed", "That program belongs to another user or the system, so Qalaa can't pause or stop it.");
      throw error;
    }
  }

  async suspend(id: unknown): Promise<CredentialStatus> {
    const incident = this.find(id);
    await this.send(incident, "SIGSTOP");
    incident.state = "suspended";
    return this.status();
  }

  async resume(id: unknown): Promise<CredentialStatus> {
    const incident = this.find(id);
    if (incident.state !== "suspended") throw new IpcError("bad_params", "That program isn't paused.");
    await this.send(incident, "SIGCONT");
    incident.state = "open";
    return this.status();
  }

  async terminate(id: unknown): Promise<CredentialStatus> {
    const incident = this.find(id);
    await this.send(incident, "SIGKILL");
    incident.state = "terminated";
    return this.status();
  }

  /** Trusts the program from now on (by its full path when known) and resumes it if paused. */
  async allow(id: unknown): Promise<CredentialStatus> {
    const incident = this.find(id);
    if (incident.state === "suspended") await this.send(incident, "SIGCONT").catch(() => undefined);
    // Pinned to this exact binary: a different file at the same path is reported again.
    const sha256 = await this.hashFile(incident.exe);
    this.trusted = [...this.trusted.filter((t) => t.exe !== incident.exe), { exe: incident.exe, sha256 }].slice(-200);
    this.incidents = this.incidents.filter((i) => i.exe !== incident.exe);
    await this.save();
    return this.status();
  }

  async dismiss(id: unknown): Promise<CredentialStatus> {
    const incident = this.find(id);
    this.incidents = this.incidents.filter((i) => i !== incident);
    return this.status();
  }

  async untrust(exe: unknown): Promise<CredentialStatus> {
    if (typeof exe !== "string") throw new IpcError("bad_params", "Expected a program.");
    this.trusted = this.trusted.filter((t) => t.exe !== exe);
    await this.save();
    return this.status();
  }
}
