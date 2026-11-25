/**
 * Clipboard auto-clear as a service, shared by the background service and the
 * classic app. Polls the clipboard while on, arms a countdown when a secret
 * appears (or Qalaa copies one), and clears it when time is up, only if the
 * same secret is still there. Clients get `clipboard.armed` / `clipboard.cleared`
 * events and the remaining time, never the text.
 */
import { type ClipboardIo, type SecretKind, classifySecret, digest } from "../engine/clipboard";
import type { Emit } from "./handlers";
import { IpcError } from "./protocol";

export const DEFAULT_TTL_SECONDS = 30;
export const POLL_MS = 2_000;

export interface ClipboardStatus {
  supported: boolean;
  enabled: boolean;
  ttlSeconds: number;
  armed: { kind: SecretKind; expiresAt: string; remainingMs: number } | null;
}

interface Armed {
  hash: string;
  kind: SecretKind;
  expiresAt: number;
}

export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const realClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => {
    const t = setTimeout(fn, ms);
    t.unref?.();
    return t;
  },
  clearTimeout: (h) => clearTimeout(h as NodeJS.Timeout),
};

export class ClipboardService {
  private armed: Armed | null = null;
  private timer: unknown = null;
  private lastSeen: string | null = null;
  private ttlSeconds = DEFAULT_TTL_SECONDS;
  private enabled = true;

  constructor(
    private readonly io: ClipboardIo | null,
    private readonly emit: Emit,
    private readonly clock: Clock = realClock,
  ) {}

  configure(options: { enabled?: boolean; ttlSeconds?: number }): void {
    if (options.ttlSeconds !== undefined) this.ttlSeconds = options.ttlSeconds;
    if (options.enabled !== undefined) {
      this.enabled = options.enabled;
      if (!options.enabled) this.disarm();
    }
  }

  status(): ClipboardStatus {
    const now = this.clock.now();
    return {
      supported: this.io !== null,
      enabled: this.enabled,
      ttlSeconds: this.ttlSeconds,
      armed: this.armed ? { kind: this.armed.kind, expiresAt: new Date(this.armed.expiresAt).toISOString(), remainingMs: Math.max(0, this.armed.expiresAt - now) } : null,
    };
  }

  /** One look at the clipboard: arms a countdown when a new secret appears. */
  async poll(): Promise<void> {
    if (!this.io || !this.enabled) return;
    const text = await this.io.read();
    if (text === null) return;
    const hash = digest(text);
    if (hash === this.lastSeen) return;
    this.lastSeen = hash;
    if (this.armed && this.armed.hash !== hash) this.disarm(); // replaced by something else: nothing to clear
    const kind = classifySecret(text);
    if (kind) this.arm(hash, kind);
  }

  /** Qalaa itself copies a secret (a TOTP code, a password): always cleared after the TTL. */
  async copySecret(text: unknown): Promise<ClipboardStatus> {
    if (!this.io) throw new IpcError("unavailable", "The clipboard can't be reached on this system.");
    if (typeof text !== "string" || !text || text.length > 16 * 1024) throw new IpcError("bad_params", "Expected the text to copy.");
    await this.io.write(text);
    const hash = digest(text);
    this.lastSeen = hash;
    this.arm(hash, classifySecret(text) ?? "copied_from_qalaa");
    return this.status();
  }

  /** Puts ordinary (non-secret) text on the clipboard, with no countdown. */
  async copyPlain(text: string): Promise<void> {
    if (!this.io) throw new IpcError("unavailable", "The clipboard can't be reached on this system.");
    await this.io.write(text);
    this.lastSeen = digest(text);
  }

  async clearNow(): Promise<ClipboardStatus> {
    if (this.armed) await this.expire("now");
    return this.status();
  }

  private arm(hash: string, kind: SecretKind): void {
    this.disarm();
    const ttlMs = this.ttlSeconds * 1000;
    this.armed = { hash, kind, expiresAt: this.clock.now() + ttlMs };
    this.timer = this.clock.setTimeout(() => void this.expire("timer"), ttlMs);
    this.emit("clipboard.armed", { kind, expiresAt: new Date(this.armed.expiresAt).toISOString(), ttlMs });
  }

  private disarm(): void {
    if (this.timer !== null) this.clock.clearTimeout(this.timer);
    this.timer = null;
    this.armed = null;
  }

  private async expire(reason: "timer" | "now"): Promise<void> {
    const armed = this.armed;
    this.disarm();
    if (!armed || !this.io) return;
    const current = await this.io.read();
    // Only wipe our secret: if the person copied something else since, leave it.
    if (current !== null && digest(current) !== armed.hash) return;
    await this.io.clear();
    this.lastSeen = digest("");
    this.emit("clipboard.cleared", { kind: armed.kind, reason });
  }
}
