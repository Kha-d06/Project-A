/**
 * New listening-port alerts as a service: keeps the baseline file, checks on a
 * schedule, reports new listeners as `alert` events, and applies block rules.
 * Shared by the headless daemon and the Electron shell.
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

import { EMPTY_BASELINE, type ElevatedCommand, type Listener, type ListenerBaseline, blockCommand, describeBlock, diffListeners, setBlocked, trust, validPort, withKeys } from "../engine/listeners";
import type { ListeningPort } from "../engine/security";
import type { Emit } from "./handlers";
import { IpcError } from "./protocol";
import { atomicWrite } from "./atomic-write";

export interface ListenerStatus {
  /** Everything listening now; `fresh` marks the ones waiting for a decision. */
  listeners: (Listener & { fresh: boolean })[];
  blockedPorts: number[];
  canBlock: boolean;
  checkedAt: string | null;
}

export function runElevated(command: ElevatedCommand): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(command.command, command.args, { timeout: 120_000, windowsHide: true }, (error, _stdout, stderr) =>
      error ? reject(new Error(String(stderr || error.message).trim().slice(0, 300))) : resolve(),
    );
  });
}

export class ListenerService {
  private baseline: ListenerBaseline = EMPTY_BASELINE;
  private current: Listener[] = [];
  private fresh = new Set<string>();
  private checkedAt: string | null = null;

  constructor(
    private readonly file: string,
    private readonly platform: NodeJS.Platform,
    private readonly list: () => Promise<ListeningPort[] | null>,
    private readonly emit: Emit,
    private readonly exec: (command: ElevatedCommand) => Promise<void> = runElevated,
  ) {}

  async load(): Promise<void> {
    try {
      this.baseline = { ...EMPTY_BASELINE, ...(JSON.parse(await readFile(this.file, "utf8")) as Partial<ListenerBaseline>) };
    } catch {
      this.baseline = EMPTY_BASELINE;
    }
  }

  private save(): Promise<void> {
    return atomicWrite(this.file, JSON.stringify(this.baseline));
  }

  /** Looks at what listens now; alerts once for each new reachable listener. */
  async check(): Promise<Listener[]> {
    const ports = await this.list();
    if (!ports) return [];
    this.current = withKeys(ports);
    this.checkedAt = new Date().toISOString();
    const { fresh, baseline } = diffListeners(this.baseline, ports);
    this.baseline = baseline;
    const reported = fresh.filter((l) => !this.fresh.has(l.key));
    for (const l of fresh) this.fresh.add(l.key);
    // Listeners that went away no longer wait for a decision.
    for (const key of [...this.fresh]) if (!this.current.some((l) => l.key === key)) this.fresh.delete(key);
    await this.save();
    for (const l of reported) this.emit("alert", { kind: "listener", key: l.key, port: l.port, process: l.process, risk: l.risk });
    return reported;
  }

  newCount(): number {
    return this.fresh.size;
  }

  canBlock(): boolean {
    return this.platform === "linux" || this.platform === "win32" || this.platform === "darwin";
  }

  status(): ListenerStatus {
    return {
      listeners: this.current.map((l) => ({ ...l, fresh: this.fresh.has(l.key) })),
      blockedPorts: this.baseline.blockedPorts,
      canBlock: this.canBlock(),
      checkedAt: this.checkedAt,
    };
  }

  async trust(key: unknown): Promise<ListenerStatus> {
    if (typeof key !== "string" || key.length > 300) throw new IpcError("bad_params", "Expected a listener key.");
    this.baseline = trust(this.baseline, key);
    this.fresh.delete(key);
    await this.save();
    return this.status();
  }

  /** Shows the system's consent prompt; nothing changes if the person declines. */
  async block(port: unknown, block: unknown): Promise<ListenerStatus & { change: string }> {
    if (!validPort(port)) throw new IpcError("bad_params", "Expected a port from 1 to 65535.");
    if (typeof block !== "boolean") throw new IpcError("bad_params", "Expected block: true or false.");
    if (!this.canBlock()) throw new IpcError("unavailable", "Blocking ports isn't available on this system.");
    const next = setBlocked(this.baseline, port, block);
    await this.exec(blockCommand(this.platform, next.blockedPorts, port, block));
    this.baseline = next;
    for (const l of this.current) if (l.port === port && block) this.fresh.delete(l.key);
    await this.save();
    return { ...this.status(), change: describeBlock(this.platform, port, block) };
  }
}
