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

import { type CredentialKind, type OpenFile, credentialKind, displayPath, exeOf, isAllowed, parseLsof, procOpenFiles, programName } from "../engine/credentials";
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
}

export interface CredentialStatus {
  supported: boolean;
  enabled: boolean;
  mode: GuardMode;
  /** Newest first; open and suspended ones wait for a decision. */
  incidents: CredentialIncident[];
  trusted: string[];
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
  now?: () => number;
  selfPid?: number;
}

const MAX_INCIDENTS = 20;
const MAX_SEEN = 2_000;

export function pollMs(platform: NodeJS.Platform): number {
  return platform === "darwin" ? 15_000 : 5_000;
}

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
    // lsof exits 1 when some files can't be listed but still prints the rest.
    return async () => parseLsof(await run("lsof", ["-u", userInfo().username, "-Fpcn", "-n", "-P"]).catch(() => "")).filter((f) => interesting(f.path));
  }
  return undefined;
}

export function defaultExeOf(platform: NodeJS.Platform): (pid: number) => Promise<string | null> {
  if (platform === "darwin") return async (pid) => (await run("ps", ["-p", String(pid), "-o", "comm="]).catch(() => "")).trim() || null;
  return (pid) => exeOf(pid, platform);
}

export class CredentialGuardService {
  private trusted: string[] = [];
  private incidents: CredentialIncident[] = [];
  private seen = new Set<string>();
  private enabled = true;
  private everyOpen = false;
  private counter = 0;
  private readonly source: CredentialGuardDeps["source"];
  private readonly exeOf: (pid: number) => Promise<string | null>;
  private readonly signal: (pid: number, signal: Signal) => void;
  private readonly now: () => number;
  private readonly selfPid: number;

  constructor(private readonly deps: CredentialGuardDeps) {
    this.source = deps.source ?? defaultSource(deps.platform, deps.home);
    this.exeOf = deps.exeOf ?? defaultExeOf(deps.platform);
    this.signal = deps.signal ?? ((pid, sig) => process.kill(pid, sig));
    this.now = deps.now ?? Date.now;
    this.selfPid = deps.selfPid ?? process.pid;
  }

  async load(): Promise<void> {
    try {
      const saved = JSON.parse(await readFile(this.deps.file, "utf8")) as { trusted?: unknown };
      this.trusted = Array.isArray(saved.trusted) ? saved.trusted.filter((t): t is string => typeof t === "string").slice(0, 200) : [];
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
    return { supported: this.isSupported(), enabled: this.enabled, mode: this.mode(), incidents: this.incidents.map((i) => ({ ...i })), trusted: [...this.trusted] };
  }

  /** One open of `path` by `pid`. Cheap for every other file: the path is classified first. */
  async observe(pid: number, path: string, exe?: string): Promise<CredentialIncident | null> {
    if (!this.enabled || pid === this.selfPid || pid <= 0) return null;
    const credential = credentialKind(path, this.deps.home);
    if (!credential) return null;
    const seenKey = `${pid}\0${path}`;
    if (this.seen.has(seenKey)) return null;
    const program = exe ?? (await this.exeOf(pid)) ?? "unknown";
    if (isAllowed(credential, program, this.trusted)) return null;
    this.remember(seenKey);
    const incident: CredentialIncident = {
      id: `c${this.now().toString(36)}${(this.counter++).toString(36)}`,
      pid,
      program: programName(program),
      exe: program,
      credential,
      file: displayPath(path, this.deps.home),
      at: new Date(this.now()).toISOString(),
      state: "open",
    };
    this.incidents = [incident, ...this.incidents].slice(0, MAX_INCIDENTS);
    this.deps.emit("alert", { kind: "credential", id: incident.id, pid, program: incident.program, credential, file: incident.file });
    return incident;
  }

  /** One look at what is open now; returns new incidents. */
  async poll(): Promise<CredentialIncident[]> {
    if (!this.enabled || !this.source) return [];
    const files = (await this.source()) ?? [];
    const found: CredentialIncident[] = [];
    for (const f of files) {
      const incident = await this.observe(f.pid, f.path, f.exe);
      if (incident) found.push(incident);
    }
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
    if (!this.trusted.includes(incident.exe)) this.trusted = [...this.trusted, incident.exe].slice(-200);
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
    this.trusted = this.trusted.filter((t) => t !== exe);
    await this.save();
    return this.status();
  }
}
