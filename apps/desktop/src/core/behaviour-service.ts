/**
 * Behaviour rules over newly started programs (Wave 4.B, first slice).
 *
 * Each look lists running programs, picks the ones that started since the
 * last look, and checks them against the Sigma-derived rules. A match is an
 * alert the person can dismiss, or stop the program. Only the rule, the
 * program, its parent and a shortened, masked command line are kept.
 */
import { basename } from "node:path";

import catalog from "./data/behaviour-rules.json";
import { type BehaviourRule, type ProcessEvent, matches, redactCommandLine, rulesFor, validateRule } from "../engine/behaviour-rules";
import { type FeedCapability, type ProcessRow, ProcessDiff, capabilityFor, defaultRows } from "../engine/process-feed";
import type { Emit } from "./handlers";
import { IpcError } from "./protocol";

export interface BehaviourIncident {
  id: string;
  rule: string;
  title: string;
  description: string;
  technique: string;
  level: BehaviourRule["level"];
  pid: number;
  program: string;
  parent: string;
  commandLine: string;
  at: string;
  state: "open" | "stopped" | "dismissed";
}

export interface BehaviourStatus {
  enabled: boolean;
  capability: FeedCapability;
  rules: number;
  rulesVersion: string;
  incidents: BehaviourIncident[];
}

export interface BehaviourDeps {
  platform: NodeJS.Platform;
  emit: Emit;
  rows?: () => Promise<ProcessRow[]>;
  rules?: BehaviourRule[];
  now?: () => number;
  selfPid?: number;
  /** Current command line of a pid, to check it is still the same program before stopping it. */
  commandOf?: (pid: number) => Promise<string | null>;
  signal?: (pid: number, signal: "SIGKILL") => void;
}

const MAX_INCIDENTS = 50;
/** One alert per rule and program in this window, so a loop doesn't flood. */
const REPEAT_MS = 10 * 60 * 1000;

export const BUILT_IN_RULES: BehaviourRule[] = (catalog as unknown as { rules: BehaviourRule[] }).rules;
export const RULES_VERSION: string = (catalog as { version: string }).version;

export class BehaviourService {
  private readonly diff = new ProcessDiff();
  private readonly rules: BehaviourRule[];
  private readonly rows: BehaviourDeps["rows"];
  private readonly now: () => number;
  private incidents: BehaviourIncident[] = [];
  private lastAlert = new Map<string, number>();
  private enabled = true;
  private counter = 0;
  private inFlight: Promise<BehaviourIncident[]> | null = null;

  constructor(private readonly deps: BehaviourDeps) {
    const all = deps.rules ?? BUILT_IN_RULES;
    all.forEach(validateRule);
    this.rules = rulesFor(all, deps.platform);
    this.rows = deps.rows ?? defaultRows(deps.platform);
    this.now = deps.now ?? Date.now;
  }

  capability(): FeedCapability {
    return capabilityFor(this.deps.platform);
  }

  isSupported(): boolean {
    return this.rows !== undefined && this.rules.length > 0;
  }

  configure(options: { enabled?: boolean }): void {
    if (options.enabled !== undefined) this.enabled = options.enabled;
  }

  /** One look; overlapping calls share it. */
  poll(): Promise<BehaviourIncident[]> {
    this.inFlight ??= this.look().finally(() => (this.inFlight = null));
    return this.inFlight;
  }

  private async look(): Promise<BehaviourIncident[]> {
    if (!this.enabled || !this.rows) return [];
    const events = this.diff.next(await this.rows(), this.now());
    return events.flatMap((e) => this.check(e));
  }

  /** Rules against one event (also used directly by tests and a future event-driven source). */
  check(event: ProcessEvent): BehaviourIncident[] {
    if (event.pid === (this.deps.selfPid ?? process.pid) || event.ppid === (this.deps.selfPid ?? process.pid)) return [];
    const found: BehaviourIncident[] = [];
    for (const rule of this.rules) {
      if (!matches(rule, event)) continue;
      const program = basename(event.image) || event.image;
      const key = `${rule.id}\0${program}`;
      const last = this.lastAlert.get(key);
      if (last !== undefined && this.now() - last < REPEAT_MS) continue;
      this.lastAlert.set(key, this.now());
      if (this.lastAlert.size > 1000) this.lastAlert.delete(this.lastAlert.keys().next().value!);
      const incident: BehaviourIncident = {
        id: `b${this.now().toString(36)}${(this.counter++).toString(36)}`,
        rule: rule.id,
        title: rule.title,
        description: rule.description,
        technique: rule.technique,
        level: rule.level,
        pid: event.pid,
        program,
        parent: basename(event.parentImage) || event.parentImage,
        commandLine: redactCommandLine(event.commandLine),
        at: new Date(this.now()).toISOString(),
        state: "open",
      };
      this.incidents = [incident, ...this.incidents].slice(0, MAX_INCIDENTS);
      this.deps.emit("alert", { kind: "behaviour", id: incident.id, rule: rule.id, technique: rule.technique, level: rule.level, pid: event.pid, program, parent: incident.parent });
      found.push(incident);
    }
    return found;
  }

  pendingCount(): number {
    return this.incidents.filter((i) => i.state === "open").length;
  }

  status(): BehaviourStatus {
    return { enabled: this.enabled, capability: this.capability(), rules: this.rules.length, rulesVersion: RULES_VERSION, incidents: this.incidents.map((i) => ({ ...i })) };
  }

  private find(id: unknown): BehaviourIncident {
    if (typeof id !== "string" || id.length > 64) throw new IpcError("bad_params", "Expected an alert id.");
    const incident = this.incidents.find((i) => i.id === id);
    if (!incident) throw new IpcError("not_found", "That alert is no longer listed.");
    return incident;
  }

  dismiss(id: unknown): BehaviourStatus {
    this.find(id).state = "dismissed";
    return this.status();
  }

  async stop(id: unknown): Promise<BehaviourStatus> {
    const incident = this.find(id);
    if (this.deps.platform === "win32") throw new IpcError("unavailable", "Stopping programs from Qalaa isn't available on Windows yet.");
    const current = await (this.deps.commandOf ?? defaultCommandOf)(incident.pid);
    // The pid may have been reused: only stop it if it still runs the same command.
    if (!current || redactCommandLine(current) !== incident.commandLine) throw new IpcError("not_found", "That program has already closed.");
    try {
      (this.deps.signal ?? ((pid, sig) => process.kill(pid, sig)))(incident.pid, "SIGKILL");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ESRCH") throw new IpcError("not_found", "That program has already closed.");
      if (code === "EPERM") throw new IpcError("not_allowed", "That program belongs to another user or the system, so Qalaa can't stop it.");
      throw error;
    }
    incident.state = "stopped";
    return this.status();
  }
}

async function defaultCommandOf(pid: number): Promise<string | null> {
  const { readFile } = await import("node:fs/promises");
  if (process.platform === "linux") {
    const raw = await readFile(`/proc/${pid}/cmdline`, "utf8").catch(() => "");
    return raw ? raw.split("\0").filter(Boolean).join(" ") : null;
  }
  const { execFile } = await import("node:child_process");
  return new Promise((resolve) => execFile("ps", ["-ww", "-o", "command=", "-p", String(pid)], { timeout: 5_000 }, (e, out) => resolve(e ? null : String(out).trim() || null)));
}
