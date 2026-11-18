/**
 * Behavioural ransomware blocking.
 *
 * The on-access helper reports which process opens which file. Ransomware shows
 * itself by opening a burst of different files under the person's documents in
 * a few seconds, and/or writing files with an extension known from ransomware.
 * When a process crosses that line this flags it so the helper can freeze it
 * (SIGSTOP) before more files are lost, and the app can ask what to do.
 *
 * Pure and deterministic so it can be tested without touching the kernel.
 */
import { extname } from "node:path";

export const BURST_FILES = 40; // distinct files one process touches…
export const BURST_WINDOW_MS = 5_000; // …within this window
export const RANSOM_RENAMES = 6; // or this many ransom-extension files

const RANSOM_EXTENSIONS =
  /\.(locked|encrypted|enc|crypt|crypted|crypto|lockbit|ryk|conti|akira|blackcat|wncry|wcry|locky|cerber|zepto|odin|ransom)$/i;

export interface OpenEvent {
  pid: number;
  path: string;
  at: number;
}

export interface Halt {
  pid: number;
  reason: string;
  files: number;
}

/**
 * Tracks recent opens per process inside the watched folders. feed() returns a
 * Halt the first time a process looks like ransomware, then stays quiet for
 * that process (it is about to be frozen).
 */
export class RansomwareBurst {
  private readonly perPid = new Map<number, OpenEvent[]>();
  private readonly halted = new Set<number>();
  private readonly window: number;
  private readonly burst: number;

  constructor(window = BURST_WINDOW_MS, burst = BURST_FILES) {
    this.window = window;
    this.burst = burst;
  }

  feed(event: OpenEvent): Halt | null {
    if (this.halted.has(event.pid)) return null;
    const recent = (this.perPid.get(event.pid) ?? []).filter((e) => event.at - e.at <= this.window);
    // Count each file once per window.
    if (!recent.some((e) => e.path === event.path)) recent.push(event);
    this.perPid.set(event.pid, recent);

    const renamed = recent.filter((e) => RANSOM_EXTENSIONS.test(e.path)).length;
    if (renamed >= RANSOM_RENAMES) return this.trip(event.pid, `wrote ${renamed} files with a ransomware extension`, renamed);
    if (recent.length >= this.burst) return this.trip(event.pid, `changed ${recent.length} files in ${Math.round(this.window / 1000)} seconds`, recent.length);
    return null;
  }

  private trip(pid: number, reason: string, files: number): Halt {
    this.halted.add(pid);
    this.perPid.delete(pid);
    return { pid, reason, files };
  }

  /** Forget a process once it has been dealt with (resumed or killed). */
  clear(pid: number): void {
    this.halted.delete(pid);
    this.perPid.delete(pid);
  }

  isHalted(pid: number): boolean {
    return this.halted.has(pid);
  }
}

/** Whether a path is one the burst detector should count (inside watched roots). */
export function underAny(path: string, roots: string[]): boolean {
  return roots.some((root) => path === root || path.startsWith(root.endsWith("/") ? root : `${root}/`));
}

/** A file whose extension alone marks it as ransomware output. */
export function looksEncrypted(path: string): boolean {
  return RANSOM_EXTENSIONS.test(extname(path)) || RANSOM_EXTENSIONS.test(path);
}
